package Bitcoin::Crypto::Role::BasicKey;

use v5.10;
use strict;
use warnings;
use Carp qw(carp);
use Type::Params -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Object Str ByteStr FormatStr);
use Bitcoin::Crypto::Util qw(format_as);
use Moo::Role;

with qw(
	Bitcoin::Crypto::Role::Key
	Bitcoin::Crypto::Role::Compressed
	Bitcoin::Crypto::Role::SignVerify
);

around BUILDARGS => sub {
	my ($orig, $class, @params) = @_;

	if (@params == 1) {
		carp "$class->new(\$bytes) is now deprecated. Use $class->from_str(\$bytes) instead";
		unshift @params, 'key_instance';
	}

	return $class->$orig(@params);
};

signature_for from_str => (
	method => Str,
	positional => [ByteStr],
);

sub from_str
{
	my ($class, $bytes) = @_;

	return $class->new(key_instance => $bytes);
}

signature_for to_str => (
	method => Object,
	positional => [],
);

sub to_str
{
	my ($self) = @_;

	return $self->raw_key;
}

### DEPRECATED

sub from_hex
{
	my ($class, $val) = @_;

	carp "$class->from_hex(\$str) is now deprecated. Use $class->from_str([hex => \$str]) instead";
	return $class->from_str([hex => $val]);
}

sub to_hex
{
	my ($self) = @_;

	my $class = ref $self;
	carp "$class->to_hex() is now deprecated. Use Bitcoin::Crypto::Util::format_as [hex => $class->to_str()] instead";
	return format_as [hex => $self->to_str];
}

sub from_bytes
{
	my ($class, $bytes) = @_;

	carp "$class->from_bytes() is now deprecated. Use $class->from_str() instead";
	return $class->from_str($bytes);
}

sub to_bytes
{
	my ($self) = @_;

	my $class = ref $self;
	carp "$class->to_bytes() is now deprecated. Use $class->to_str() instead";
	return $self->to_str;
}

1;

