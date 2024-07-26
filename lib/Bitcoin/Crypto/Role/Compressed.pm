package Bitcoin::Crypto::Role::Compressed;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Moo::Role;

has param 'compressed' => (
	coerce => Bool,
	default => !!1,
	writer => -hidden,
);

signature_for set_compressed => (
	method => Object,
	positional => [Bool, {default => !!1}],
);

sub set_compressed
{
	my ($self, $state) = @_;

	$self->_set_compressed($state);
	return $self;
}

1;

