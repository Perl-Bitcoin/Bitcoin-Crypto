package Bitcoin::Crypto::Role::Compressed;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Moo::Role;
use Carp qw(carp);

has param 'compressed' => (
	coerce => Bool,
	default => !!1,
	writer => -hidden,
);

signature_for set_compressed => (
	method => Object,
	positional => [Maybe [Bool], {default => undef}],
);

sub set_compressed
{
	my ($self, $state) = @_;

	carp 'set_compressed without argument is deprecated: use set_compressed(1) instead'
		unless defined $state;

	$self->_set_compressed($state // !!1);

	# chainable - undocumented behavior, but kept for backcompat
	return $self;
}

1;

