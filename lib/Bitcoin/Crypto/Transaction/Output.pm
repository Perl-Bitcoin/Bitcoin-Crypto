package Bitcoin::Crypto::Transaction::Output;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Int BitcoinScript InstanceOf Object Str ByteStr PositiveOrZeroInt ScalarRef);
use Bitcoin::Crypto::Helpers qw(pack_varint unpack_varint ensure_length);    # loads BigInt
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Exception;

has param 'value' => (
	writer => 1,
	coerce => (InstanceOf ['Math::BigInt'])
		->where(q{$_ >= 0})
		->plus_coercions(Int | Str, q{ Math::BigInt->new($_) }),
);

has param 'locking_script' => (
	coerce => BitcoinScript,
	writer => 1,
);

with qw(
	Bitcoin::Crypto::Role::ShallowClone
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

signature_for set_max_value => (
	method => Object,
	positional => [],
);

sub set_max_value
{
	my ($self) = @_;

	$self->set_value('0xffffffffffffffff');
	return $self;
}

sub value_serialized
{
	my ($self) = @_;

	# NOTE: little endian
	my $value = $self->value->as_bytes;
	return scalar reverse ensure_length($value, 8);
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

	$serialized .= $self->value_serialized;

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

signature_for dump => (
	method => Object,
	named => [
	],
);

sub dump
{
	my ($self, $params) = @_;

	my $type = $self->locking_script->type // 'Custom';

	my @result;
	push @result, "$type Output";
	push @result, 'value: ' . $self->value;
	push @result, 'locking script: ' . to_format [hex => $self->locking_script->to_serialized];

	return join "\n", @result;
}

1;

