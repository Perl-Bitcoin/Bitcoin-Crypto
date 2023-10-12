package Bitcoin::Crypto::Script::Transaction;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Object InstanceOf PositiveOrZeroInt ByteStr);
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

signature_for get_digest => (
	method => Object,
	positional => [ByteStr, PositiveOrZeroInt],
);

sub get_digest
{
	my ($self, $subscript, $sighash) = @_;

	return $self->transaction->get_digest(
		signing_index => $self->input_index,
		signing_subscript => $subscript,
		sighash => $sighash
	);
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

1;

