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

sub _digest_input
{
	my ($self, $input, $signed) = @_;

	my $cloned = $input->clone;

	if ($signed && $self->signing_subscript) {
		$cloned->set_signature_script($self->signing_subscript);
	}
	elsif ($signed) {
		$cloned->set_signature_script($input->script_base);
	}
	else {
		$cloned->set_signature_script("\x00");
	}

	return $cloned->to_serialized;
}

sub _get_digest_default
{
	my ($self, $this_input, $sighash_type, $anyonecanpay) = @_;
	my $transaction = $self->transaction;

	# Digest result is similar to transaction serialization, but it never
	# contains witness data and the signature script of inputs is altered

	my $serialized = '';

	$serialized .= pack 'V', $transaction->version;

	# Process inputs
	my @inputs = @{$transaction->inputs};
	$serialized .= pack_varint(scalar @inputs);
	foreach my $input (@inputs) {
		$serialized .= $self->_digest_input($input, $input == $this_input);
	}

	# Process outputs
	my @outputs = @{$transaction->outputs};
	Bitcoin::Crypto::Exception::Transaction->raise(
		'transaction has no outputs'
	) if @outputs == 0;

	$serialized .= pack_varint(scalar @outputs);
	foreach my $item (@outputs) {
		$serialized .= $item->to_serialized;
	}

	$serialized .= pack 'V', $transaction->locktime;

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

	my $script_base = $this_input->script_base;
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

	return hash256($serialized);
}

1;

