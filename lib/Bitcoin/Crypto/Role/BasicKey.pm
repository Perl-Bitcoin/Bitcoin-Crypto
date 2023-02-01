package Bitcoin::Crypto::Role::BasicKey;

use v5.10;
use strict;
use warnings;
use Carp qw(carp);
use Type::Params -sigs;

use Bitcoin::Crypto::Helpers qw(pad_hex);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Object Str ByteStr);
use Moo::Role;

with qw(
	Bitcoin::Crypto::Role::Key
	Bitcoin::Crypto::Role::Compressed
	Bitcoin::Crypto::Role::DSA
);

around BUILDARGS => sub {
	my ($orig, $class, @params) = @_;

	if (@params == 1) {
		carp "$class->new(\$bytes) is now deprecated. Use $class->from_bytes(\$bytes) instead";
		unshift @params, 'key_instance';
	}

	return $class->$orig(@params);
};

signature_for from_hex => (
	method => Str,
	positional => [Str],
);

sub from_hex
{
	my ($class, $val) = @_;
	return $class->from_bytes(pack 'H*', pad_hex($val));
}

signature_for to_hex => (
	method => Object,
	positional => [],
);

sub to_hex
{
	my ($self) = @_;
	return unpack 'H*', $self->to_bytes();
}

signature_for from_bytes => (
	method => Str,
	positional => [ByteStr],
);

sub from_bytes
{
	my ($class, $bytes) = @_;

	return $class->new(key_instance => $bytes);
}

signature_for to_bytes => (
	method => Object,
	positional => [],
);

sub to_bytes
{
	my ($self) = @_;
	return $self->raw_key;
}

1;

