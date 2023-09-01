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
use Bitcoin::Crypto::Types qw(InstanceOf ByteStr PositiveInt PositiveOrZeroInt);

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
);

has param 'signing_index' => (
	isa => PositiveOrZeroInt,
);

has option 'signing_subscript' => (
	isa => ByteStr,
);

has param 'sighash' => (
	isa => PositiveInt,
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

	my $sighash_type = $self->sighash & 31;
	my $anyonecanpay = $self->sighash & Bitcoin::Crypto::Constants::sighash_anyonecanpay;

	# TODO: handle sighashes other than ALL

	return $self->$procedure($input, $sighash_type, $anyonecanpay);
}

sub _get_digest_default
{
	my ($self, $this_input, $sighash_type, $anyonecanpay) = @_;
	my $transaction = $self->transaction;
	my $tx_copy = $transaction->clone;

	@{$tx_copy->inputs} = ();
	foreach my $input (@{$transaction->inputs}) {
		my $input_copy = $input->clone;
		my $signed = $input == $this_input;

		if ($signed && $self->signing_subscript) {
			$input_copy->set_signature_script($self->signing_subscript);
		}
		elsif ($signed) {
			Bitcoin::Crypto::Exception::Transaction->raise(
				"can't guess the subscript from a non-standard transaction"
			) unless $input->utxo->output->is_standard;

			$input_copy->set_signature_script($input->script_base->to_serialized);
		}
		elsif (!$input->signature_script->is_empty) {
			$input_copy->set_signature_script("\x00");
		}

		$tx_copy->add_input($input_copy);
	}

	my $serialized = $tx_copy->to_serialized(witness => 0);

	if ($sighash_type == Bitcoin::Crypto::Constants::sighash_none) {

		# TODO
	}
	elsif ($sighash_type == Bitcoin::Crypto::Constants::sighash_single) {

		# TODO
	}

	if ($anyonecanpay) {

		# TODO
	}

	$serialized .= pack 'V', $self->sighash;

	return $serialized;
}

sub _get_digest_segwit
{
	my ($self, $this_input, $sighash_type, $anyonecanpay) = @_;
	my $transaction = $self->transaction;

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
		push @outputs, $output->value_serialized;

		my $tmp = $output->locking_script->to_serialized;
		push @outputs, pack_varint(length $tmp) . $tmp;
	}

	$serialized .= hash256(join '', @prevouts);
	$serialized .= hash256(join '', @sequences);
	$serialized .= $this_input->prevout;

	my $script_base = $this_input->script_base->to_serialized;
	$serialized .= pack_varint(length $script_base);
	$serialized .= $script_base;

	$serialized .= $this_input->utxo->output->value_serialized;
	$serialized .= pack 'V', $this_input->sequence_no;
	$serialized .= hash256(join '', @outputs);

	if ($sighash_type == Bitcoin::Crypto::Constants::sighash_none) {

		# TODO
	}
	elsif ($sighash_type == Bitcoin::Crypto::Constants::sighash_single) {

		# TODO
	}

	if ($anyonecanpay) {

		# TODO
	}

	$serialized .= pack 'V', $transaction->locktime;
	$serialized .= pack 'V', $self->sighash;

	return $serialized;
}

1;

