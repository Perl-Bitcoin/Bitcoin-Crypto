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

around BUILDARGS => sub {
	my ($orig, $class, @params) = @_;

	if (@params == 1) {
		carp "$class->new(\$bytes) is now deprecated. Use $class->from_serialized(\$bytes) instead";
		unshift @params, 'key_instance';
	}

	return $class->$orig(@params);
};

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

### DEPRECATED

sub from_hex
{
	my ($class, $val) = @_;

	carp "$class->from_hex(\$str) is now deprecated. Use $class->from_serialized([hex => \$str]) instead";
	return $class->from_serialized([hex => $val]);
}

sub to_hex
{
	my ($self) = @_;

	my $class = ref $self;
	carp
		"$class->to_hex() is now deprecated. Use Bitcoin::Crypto::Util::to_format [hex => $class->to_serialized()] instead";
	return to_format [hex => $self->to_serialized];
}

sub from_bytes
{
	my ($class, $bytes) = @_;

	carp "$class->from_bytes() is now deprecated. Use $class->from_serialized() instead";
	return $class->from_serialized($bytes);
}

sub to_bytes
{
	my ($self) = @_;

	my $class = ref $self;
	carp "$class->to_bytes() is now deprecated. Use $class->to_serialized() instead";
	return $self->to_serialized;
}

1;

# Internal use only

