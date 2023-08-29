package Bitcoin::Crypto::Role::ShallowClone;

use v5.10;
use strict;
use warnings;

use Type::Params -sigs;
use Bitcoin::Crypto::Types qw(Object);
use Moo::Role;

signature_for clone => (
	method => Object,
	positional => [
	],
);

sub clone
{
	my ($self) = @_;

	# Don't use the constructor because not all state may be assignable this
	# way
	return bless {%$self}, ref $self;
}

1;

