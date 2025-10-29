package Bitcoin::Crypto::Script::Transaction;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

use namespace::clean;

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
	handles => [
		qw(
			version
			locktime
			inputs
			outputs
		)
	],
);

has param 'input_index' => (
	isa => PositiveOrZeroInt,
	writer => 1,
	default => 0,
);

has param 'taproot_ext_flag' => (
	isa => PositiveOrZeroInt,
	writer => 1,
	default => 0,
);

has option 'taproot_script_tree' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Tree'],
	writer => 1,
);

signature_for get_digest => (
	method => Object,
	positional => [ByteStr, Maybe [PositiveOrZeroInt]],
);

sub get_digest
{
	my ($self, $subscript, $sighash) = @_;

	return $self->transaction->get_digest(
		signing_index => $self->input_index,
		signing_subscript => $subscript,
		(defined $sighash ? (sighash => $sighash) : ()),
	);
}

signature_for get_taproot_digest => (
	method => Object,
	positional => [ByteStr, Maybe [PositiveOrZeroInt], Maybe [ByteStr]],
);

sub get_taproot_digest
{
	my ($self, $subscript, $sighash, $ext) = @_;
	$ext //= '';

	return $self->transaction->get_digest(
		signing_index => $self->input_index,
		signing_subscript => $subscript,
		taproot_ext_flag => $self->taproot_ext_flag,
		(defined $sighash ? (sighash => $sighash) : ()),
	) . $ext;
}

sub this_input
{
	my ($self) = @_;

	return $self->inputs->[$self->input_index];
}

sub is_native_segwit
{
	my ($self) = @_;

	return $self->this_input->utxo->output->locking_script->is_native_segwit;
}

sub is_taproot
{
	my ($self) = @_;

	return $self->this_input->utxo->output->locking_script->is_taproot;
}

1;

