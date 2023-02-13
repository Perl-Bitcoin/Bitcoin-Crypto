package Bitcoin::Crypto::Transaction::Output;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Types qw(Int ByteStr InstanceOf Object);
use Bitcoin::Crypto::Helpers qw(pack_varint ensure_length); # loads BigInt

has param 'value' => (
	writer => 1,
	coerce => (InstanceOf['Math::BigInt'])
		->where(q{$_ > 0})
		->plus_coercions(Int, q{ Math::BigInt->new($_) }),
);

has param 'locking_script' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Script'])
		->plus_coercions(ByteStr->coercibles, q{ Bitcoin::Crypto::Script->from_serialized($_) }),
);

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

sub from_serialized
{
}

1;

