package Bitcoin::Crypto::Transaction::Output;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Int BitcoinScript InstanceOf Object Str ByteStr PositiveOrZeroInt ScalarRef);
use Bitcoin::Crypto::Helpers qw(pack_varint unpack_varint ensure_length);    # loads BigInt
use Bitcoin::Crypto::Exception;

has param 'value' => (
	writer => 1,
	coerce => (InstanceOf ['Math::BigInt'])
		->where(q{$_ >= 0})
		->plus_coercions(Int, q{ Math::BigInt->new($_) }),
);

has param 'locking_script' => (
	coerce => BitcoinScript,
);

signature_for is_standard => (
	method => Object,
	positional => [],
);

sub is_standard
{
	my ($self) = @_;

	return $self->locking_script->has_type;
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	# output should be serialized as follows:
	# - value, 8 bytes
	# - locking script length, 1-9 bytes
	# - locking script
	my $serialized = '';

	# NOTE: little endian
	my $value = $self->value->as_bytes;
	$serialized .= reverse ensure_length($value, 8);

	my $script = $self->locking_script->get_script;
	$serialized .= pack_varint(length $script);
	$serialized .= $script;

	return $serialized;
}

signature_for from_serialized => (
	method => Str,
	head => [ByteStr],
	named => [
		pos => ScalarRef [PositiveOrZeroInt],
		{optional => 1},
	],
);

sub from_serialized
{
	my ($class, $serialized, $args) = @_;
	my $partial = $args->pos;
	my $pos = $partial ? ${$args->pos} : 0;

	my $value = reverse substr $serialized, $pos, 8;
	$pos += 8;

	my ($script_size_len, $script_size) = unpack_varint(substr $serialized, $pos, 9);
	$pos += $script_size_len;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized input script data is corrupted'
	) if $pos + $script_size > length $serialized;

	my $script = substr $serialized, $pos, $script_size;
	$pos += $script_size;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized output data is corrupted'
	) if !$partial && $pos != length $serialized;

	${$args->pos} = $pos
		if $partial;

	return $class->new(
		value => Math::BigInt->from_bytes($value),
		locking_script => $script,
	);
}

1;

