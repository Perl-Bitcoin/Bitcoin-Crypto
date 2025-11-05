package Bitcoin::Crypto::Key::Base;

use v5.10;
use strict;
use warnings;
use Moo;
use Types::Common -sigs, -types;
use Carp qw(carp);

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Util qw(to_format);

use namespace::clean;

with qw(
	Bitcoin::Crypto::Role::Key
	Bitcoin::Crypto::Role::Compressed
	Bitcoin::Crypto::Role::SignVerify
);

sub _is_private
{
	die __PACKAGE__ . '::_is_private is unimplemented';
}

signature_for from_serialized => (
	method => Str,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $bytes) = @_;

	return $class->new(key_instance => $bytes);
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	return $self->raw_key;
}

1;

# Internal use only

