package Bitcoin::Crypto::Transaction::Digest;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Helpers qw(pack_varint);
use Bitcoin::Crypto::Util qw(hash256);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types qw(InstanceOf ByteStr PositiveOrZeroInt PositiveOrZeroInt);

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
);

has param 'signing_index' => (
	isa => PositiveOrZeroInt,
);

has option 'signing_subscript' => (
	coerce => ByteStr,
);

has param 'sighash' => (
	isa => PositiveOrZeroInt,
	default => Bitcoin::Crypto::Constants::sighash_all,
);

sub get_digest
{
	my ($self) = @_;
	my $sign_no = $self->signing_index;
	my $input = $self->transaction->inputs->[$sign_no];

	Bitcoin::Crypto::Exception::Transaction->raise(
		"can't find input with index $sign_no"
	) if !$input;

	my $procedure = '_get_digest_default';
	$procedure = '_get_digest_segwit'
		if $input->is_segwit;

	my $sighash_type = $self->sighash & 31 || Bitcoin::Crypto::Constants::sighash_all;
	my $anyonecanpay = $self->sighash & Bitcoin::Crypto::Constants::sighash_anyonecanpay;

	return $self->$procedure($sighash_type, $anyonecanpay);
}

sub _get_digest_default
{
	my ($self, $sighash_type, $anyonecanpay) = @_;
	my $transaction = $self->transaction;
	my $tx_copy = $transaction->clone;

	@{$tx_copy->inputs} = ();
	foreach my $input (@{$transaction->inputs}) {
		my $input_copy = $input->clone;

		$input_copy->set_signature_script('');
		$tx_copy->add_input($input_copy);
	}

	my $this_input = $tx_copy->inputs->[$self->signing_index];
	if ($self->signing_subscript) {
		$this_input->set_signature_script($self->signing_subscript);
	}
	else {
		Bitcoin::Crypto::Exception::Transaction->raise(
			"can't guess the subscript from a non-standard transaction"
		) unless $this_input->utxo->output->is_standard;

		$this_input->set_signature_script($this_input->script_base->to_serialized);
	}

	# Handle sighashes
	if ($sighash_type == Bitcoin::Crypto::Constants::sighash_none) {
		@{$tx_copy->outputs} = ();
		foreach my $input (@{$tx_copy->inputs}) {
			$input->set_sequence_no(0)
				unless $input == $this_input;
		}
	}
	elsif ($sighash_type == Bitcoin::Crypto::Constants::sighash_single) {
		if ($self->signing_index >= @{$transaction->outputs}) {

			# TODO: this should verify with digest 0000..0001 (without hashed)
			Bitcoin::Crypto::Exception::Transaction->raise(
				'illegal input ' . $self->signing_index . ' in SIGHASH_SINGLE'
			);
		}

		@{$tx_copy->outputs} = ();
		my @wanted_outputs = @{$transaction->outputs}[0 .. $self->signing_index - 1];
		foreach my $output (@wanted_outputs) {
			my $output_copy = $output->clone;
			$output_copy->set_locking_script('');
			$output_copy->set_max_value;
			$tx_copy->add_output($output_copy);
		}

		$tx_copy->add_output($transaction->outputs->[$self->signing_index]);

		foreach my $input (@{$tx_copy->inputs}) {
			$input->set_sequence_no(0)
				unless $input == $this_input;
		}
	}

	if ($anyonecanpay) {
		@{$tx_copy->inputs} = ($this_input);
	}

	my $serialized = $tx_copy->to_serialized(witness => 0);
	$serialized .= pack 'V', $self->sighash;

	return $serialized;
}

sub _get_digest_segwit
{
	my ($self, $sighash_type, $anyonecanpay) = @_;
	my $transaction = $self->transaction->clone;
	my $this_input = $transaction->inputs->[$self->signing_index]->clone;
	$transaction->inputs->[$self->signing_index] = $this_input;

	my $empty_hash = "\x00" x 32;
	my $single = $sighash_type == Bitcoin::Crypto::Constants::sighash_single;
	my $none = $sighash_type == Bitcoin::Crypto::Constants::sighash_none;

	if ($self->signing_subscript) {
		$this_input->set_witness([$self->signing_subscript]);
	}

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

	my @prevouts;
	my @sequences;
	foreach my $input (@{$transaction->inputs}) {
		push @prevouts, $input->prevout;
		push @sequences, pack 'V', $input->sequence_no;
	}

	my @outputs;
	foreach my $output (@{$transaction->outputs}) {
		my $tmp = $output->locking_script->to_serialized;
		push @outputs, $output->value_serialized . pack_varint(length $tmp) . $tmp;
	}

	# handle prevouts
	$serialized .= $anyonecanpay
		? $empty_hash
		: hash256(join '', @prevouts)
		;

	# handle sequences
	$serialized .= $anyonecanpay || $single || $none
		? $empty_hash
		: hash256(join '', @sequences)
		;

	$serialized .= $this_input->prevout;

	my $script_base = $this_input->script_base->to_serialized;
	$serialized .= pack_varint(length $script_base);
	$serialized .= $script_base;

	$serialized .= $this_input->utxo->output->value_serialized;
	$serialized .= pack 'V', $this_input->sequence_no;

	# handle outputs
	if (!$single && !$none) {
		$serialized .= hash256(join '', @outputs);
	}
	elsif ($single && $self->signing_index < @outputs) {
		$serialized .= hash256($outputs[$self->signing_index]);
	}
	else {
		$serialized .= $empty_hash;
	}

	$serialized .= pack 'V', $transaction->locktime;
	$serialized .= pack 'V', $self->sighash;

	return $serialized;
}

1;

