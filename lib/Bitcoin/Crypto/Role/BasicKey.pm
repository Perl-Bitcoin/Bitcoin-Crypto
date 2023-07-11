package Bitcoin::Crypto::Role::BasicKey;

use v5.10;
use strict;
use warnings;
use Type::Params -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Object Str ByteStr FormatStr);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Helpers qw(carp_once);
use Moo::Role;

with qw(
	Bitcoin::Crypto::Role::Key
	Bitcoin::Crypto::Role::Compressed
	Bitcoin::Crypto::Role::SignVerify
);

around BUILDARGS => sub {
	my ($orig, $class, @params) = @_;

	if (@params == 1) {
		carp_once "$class->new(\$bytes) is now deprecated. Use $class->from_serialized(\$bytes) instead";
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

	carp_once "$class->from_hex(\$str) is now deprecated. Use $class->from_serialized([hex => \$str]) instead";
	return $class->from_serialized([hex => $val]);
}

sub to_hex
{
	my ($self) = @_;

	my $class = ref $self;
	carp_once
		"$class->to_hex() is now deprecated. Use Bitcoin::Crypto::Util::to_format [hex => $class->to_serialized()] instead";
	return to_format [hex => $self->to_serialized];
}

sub from_bytes
{
	my ($class, $bytes) = @_;

	carp_once "$class->from_bytes() is now deprecated. Use $class->from_serialized() instead";
	return $class->from_serialized($bytes);
}

sub to_bytes
{
	my ($self) = @_;

	my $class = ref $self;
	carp_once "$class->to_bytes() is now deprecated. Use $class->to_serialized() instead";
	return $self->to_serialized;
}

1;

