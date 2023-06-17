package Bitcoin::Crypto::Script::Transaction;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Object InstanceOf PositiveInt PositiveOrZeroInt ByteStr);
use Bitcoin::Crypto::Exception;

use namespace::clean;

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
	handles => [
		qw(
			locktime
		)
	],
);

has param 'input_index' => (
	isa => PositiveOrZeroInt,
	writer => 1,
	default => 0,
);

has field 'runner' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Runner'],
	writer => 1,
	weak_ref => 1,
);

signature_for get_digest => (
	method => Object,
	positional => [PositiveInt],
);

sub get_digest
{
	my ($self, $sighash) = @_;

	return $self->transaction->get_digest(
		signing_index => $self->input_index,
		signing_subscript => $self->runner->subscript,
		sighash => $sighash
	);
}

1;

