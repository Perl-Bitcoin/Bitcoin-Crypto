package Bitcoin::Crypto::Transaction::Digest;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Util qw(hash256 pack_compactsize);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants qw(:sighash);
use Bitcoin::Crypto::Transaction::Digest::Config;
use Bitcoin::Crypto::Transaction::Digest::Result;

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
	weak_ref => 1,
);

has field 'config' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Transaction::Digest::Config'])
		->plus_coercions(HashRef, q{Bitcoin::Crypto::Transaction::Digest::Config->new($_)}),
	writer => 1,
	handles => [
		qw(
			signing_index
			signing_subscript
			sighash
			_default_sighash
			taproot_ext_flag
			taproot_ext
			taproot_annex
		)
	],
);

has field '_cache' => (
	isa => HashRef,
	default => sub { {} },
);

sub get_digest
{
	my ($self) = @_;
	my $input = $self->transaction->inputs->[$self->signing_index];

	Bitcoin::Crypto::Exception::Transaction->raise(
		"can't find input with index " . $self->signing_index
	) unless $input;

	my $procedure = '_get_digest_default';
	if ($input->is_taproot) {
		$procedure = '_get_digest_taproot';
	}
	elsif ($input->is_segwit) {
		$procedure = '_get_digest_segwit';
	}

	return $self->$procedure();
}

sub _get_digest_default
{
	my ($self) = @_;

	$self->_default_sighash(SIGHASH_ALL);

	my $sighash_type = $self->sighash & 31;
	my $anyonecanpay = $self->sighash & SIGHASH_ANYONECANPAY;

	my $transaction = $self->transaction;
	my $tx_copy = $transaction->clone;

	my $signing_index = $self->signing_index;
	my $inputs = $transaction->inputs;
	my $copy_inputs = $tx_copy->inputs;
	@{$copy_inputs} = ();

	foreach my $input_ind (keys @{$inputs}) {

		# no other inputs if anyonecanpay - skip cloning and all other work
		next if $anyonecanpay && $input_ind != $signing_index;

		my $input = $inputs->[$input_ind]->clone;

		if ($input_ind == $signing_index) {
			my $subscript = $self->signing_subscript;
			if (!$subscript) {
				Bitcoin::Crypto::Exception::Transaction->raise(
					"can't guess the subscript from a non-standard transaction"
				) unless $input->utxo->output->is_standard;

				$subscript = $input->script_base;
			}

			$input->set_signature_script($subscript);
		}
		else {
			$input->set_signature_script('');
			$input->set_sequence_no(0)
				if $sighash_type == SIGHASH_NONE
				|| $sighash_type == SIGHASH_SINGLE;
		}

		push @{$copy_inputs}, $input;
	}

	# Handle output work for sighashes
	if ($sighash_type == SIGHASH_NONE) {
		@{$tx_copy->outputs} = ();
	}
	elsif ($sighash_type == SIGHASH_SINGLE) {
		my $outputs = $transaction->outputs;
		my $copy_outputs = $tx_copy->outputs;
		@{$copy_outputs} = ();

		if ($signing_index >= @{$outputs}) {

			# this should verify with constant digest (without hashing)
			return Bitcoin::Crypto::Transaction::Digest::Result->new(
				hash => scalar reverse ensure_length("\x01", 32),
			);
		}

		foreach my $output (@{$outputs}[0 .. $signing_index - 1]) {
			my $output_copy = $output->clone;
			$output_copy->set_locking_script('');
			$output_copy->set_max_value;
			push @{$copy_outputs}, $output_copy;
		}

		push @{$copy_outputs}, $outputs->[$signing_index];
	}

	my $serialized = $tx_copy->to_serialized(witness => 0);
	$serialized .= pack 'V', $self->sighash;

	return Bitcoin::Crypto::Transaction::Digest::Result->new(preimage => $serialized);
}

sub _get_digest_segwit
{
	my ($self) = @_;

	$self->_default_sighash(SIGHASH_ALL);

	my $sighash_type = $self->sighash & 31;
	my $anyonecanpay = $self->sighash & SIGHASH_ANYONECANPAY;

	my $signing_index = $self->signing_index;
	my $transaction = $self->transaction;
	my @inputs = @{$transaction->inputs};
	my $this_input = $inputs[$signing_index]->clone;
	$inputs[$signing_index] = $this_input;

	my $empty_hash = "\x00" x 32;
	my $single = $sighash_type == SIGHASH_SINGLE;
	my $none = $sighash_type == SIGHASH_NONE;

	# NOTE: sets witness for proper behavior of _script_code in
	# Bitcoin::Crypto::Transaction::Input for P2WSH
	$this_input->set_witness([$self->signing_subscript])
		if $self->signing_subscript;

	# According to https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
	# Double SHA256 of the serialization of:
	# 1. nVersion of the transaction (4-byte little endian)
	# 2. hashPrevouts (32-byte hash)
	# 3. hashSequence (32-byte hash)
	# 4. outpoint (32-byte hash + 4-byte little endian)
	# 5. scriptCode of the input (serialized as scripts inside CTxOuts)
	# 6. value of the output spent by this input (8-byte little endian)
	# 7. nSequence of the input (4-byte little endian)
	# 8. hashOutputs (32-byte hash)
	# 9. nLocktime of the transaction (4-byte little endian)
	# 10. sighash type of the signature (4-byte little endian)

	my $serialized = '';
	$serialized .= pack 'V', $transaction->version;

	# handle prevouts
	$serialized .= $anyonecanpay
		? $empty_hash
		: hash256(join '', map { $_->prevout } @inputs)
		;

	# handle sequences
	$serialized .= $anyonecanpay || $single || $none
		? $empty_hash
		: hash256(join '', map { pack 'V', $_->sequence_no } @inputs)
		;

	$serialized .= $this_input->prevout;

	my $script_base = $this_input->script_base->to_serialized;
	$serialized .= pack_compactsize(length $script_base);
	$serialized .= $script_base;

	$serialized .= $this_input->utxo->output->value_serialized;
	$serialized .= pack 'V', $this_input->sequence_no;

	# handle outputs
	if (!$single && !$none) {
		$serialized .= hash256(join '', map { $_->to_serialized } @{$transaction->outputs});
	}
	elsif ($single && $signing_index < @{$transaction->outputs}) {
		$serialized .= hash256($transaction->outputs->[$signing_index]->to_serialized);
	}
	else {
		$serialized .= $empty_hash;
	}

	$serialized .= pack 'VV', $transaction->locktime, $self->sighash;

	return Bitcoin::Crypto::Transaction::Digest::Result->new(preimage => $serialized);
}

sub _get_digest_taproot
{
	my ($self) = @_;

	$self->_default_sighash(SIGHASH_DEFAULT);

	my $sighash_type = $self->sighash & 3;
	my $anyonecanpay = $self->sighash & SIGHASH_ANYONECANPAY;

	my $signing_index = $self->signing_index;
	my $transaction = $self->transaction;
	my $this_input = $transaction->inputs->[$signing_index];
	my $annex = $self->taproot_annex;
	my $ext_flag = $self->taproot_ext_flag;

	my $all = $sighash_type == SIGHASH_ALL
		|| $sighash_type == SIGHASH_DEFAULT;
	my $single = $sighash_type == SIGHASH_SINGLE;
	my $none = $sighash_type == SIGHASH_NONE;

	Bitcoin::Crypto::Exception::Transaction->raise(
		"can't digest taproot transaction with unknown SIGHASH"
	) unless $all || $single || $none;

	# According to https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
	# SHA256 of the serialization of:
	# hash_type (1).
	# nVersion (4): the nVersion of the transaction.
	# nLockTime (4): the nLockTime of the transaction.
	# If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
	# - sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
	# - sha_amounts (32): the SHA256 of the serialization of all input amounts.
	# - sha_scriptpubkeys (32): the SHA256 of all spent outputs' scriptPubKeys, serialized as script inside CTxOut.
	# - sha_sequences (32): the SHA256 of the serialization of all input nSequence.
	# If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
	# - sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
	# spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0 if no annex is present, or 1 otherwise (the original witness stack has two or more witness elements, and the first byte of the last element is 0x50)
	# If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
	# - outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
	# - amount (8): value of the previous output spent by this input.
	# - scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
	# - nSequence (4): nSequence of this input.
	# If hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
	# - input_index (4): index of this input in the transaction input vector. Index of the first input is 0.
	# If an annex is present (the lowest bit of spend_type is set):
	# - sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex includes the mandatory 0x50 prefix.
	# If hash_type & 3 equals SIGHASH_SINGLE:
	# - sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.

	# zero is sighash epoch
	my $serialized = pack 'CCVV', 0, $self->sighash, $transaction->version, $transaction->locktime;

	if (!$anyonecanpay) {
		$serialized .= $self->_cache->{taproot_common_tx_data} //= do {
			my @prevouts;
			my @amounts;
			my @pubkeys;
			my @sequences;
			foreach my $input (@{$transaction->inputs}) {
				my $utxo_output = $input->utxo->output;
				my $pubkey = $utxo_output->locking_script->to_serialized;

				push @prevouts, $input->prevout;
				push @amounts, $utxo_output->value_serialized;
				push @pubkeys, pack_compactsize(length $pubkey) . $pubkey;
				push @sequences, pack 'V', $input->sequence_no;
			}

			sha256(join '', @prevouts)
				. sha256(join '', @amounts)
				. sha256(join '', @pubkeys)
				. sha256(join '', @sequences);
		};
	}

	my $outputs = $self->_cache->{taproot_outputs} //= [
		map { $_->to_serialized } @{$transaction->outputs}
	];

	if (!$none && !$single) {
		$serialized .= sha256(join '', @$outputs);
	}

	$serialized .= pack 'C', $ext_flag * 2 + defined $annex;

	if ($anyonecanpay) {
		my $utxo_output = $this_input->utxo->output;
		my $pubkey = $utxo_output->locking_script->to_serialized;

		$serialized .= join '',
			$this_input->prevout,
			$utxo_output->value_serialized,
			pack_compactsize(length $pubkey),
			$pubkey,
			pack 'V', $this_input->sequence_no;
	}
	else {
		$serialized .= pack 'V', $signing_index;
	}

	if (defined $annex) {
		$serialized .= sha256(pack_compactsize(length $annex) . $annex);
	}

	if ($single && $signing_index < @$outputs) {
		$serialized .= sha256($outputs->[$self->signing_index]);
	}
	elsif ($single) {
		Bitcoin::Crypto::Exception::Transaction->raise(
			"can't digest taproot transaction with SIGHASH_SINGLE without corresponding output"
		);
	}

	# BIP342 extension
	if ($ext_flag == 1) {
		$serialized .= $self->taproot_ext
			// Bitcoin::Crypto::Exception::Transaction->raise('missing taproot extension for ext_flag=1');
	}

	return Bitcoin::Crypto::Transaction::Digest::Result->new(
		taproot => !!1,
		preimage => $serialized,
	);
}

1;

