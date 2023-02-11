package Bitcoin::Crypto::Transaction::Input;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Helpers qw(pack_varint);
use Bitcoin::Crypto::Types qw(Str IntMaxBits Int ByteStr InstanceOf Object);

has param 'transaction_hash' => (
	coerce => ByteStr->create_child_type(
		constraint => q{ length $_ == 32},
		coercion => 1
	),
);

has param 'transaction_output_index' => (
	isa => IntMaxBits[32],
);

has param 'signature_script' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Script'])
		->plus_coercions(ByteStr->coercibles, q{ Bitcoin::Crypto::Script->from_serialized($_) }),
);

has param 'sequence_number' => (
	isa => IntMaxBits[32],
	default => 0xffffffff,
);

has option 'value' => (
	coerce => (InstanceOf['Math::BigInt'])
		->where(q{$_ > 0})
		->plus_coercions(Int, q{ Math::BigInt->new($_) }),
);

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	# input should be serialized as follows:
	# - transaction hash, 32 bytes
	# - transaction output index, 4 bytes
	# - signature script length, 1-9 bytes
	# - signature script
	# - sequence number, 4 bytes
	my $serialized = '';

	$serialized .= scalar reverse $self->transaction_hash;

	$serialized .= pack 'V', $self->transaction_output_index;

	my $script = $self->signature_script->get_script;
	$serialized .= pack_varint(length $script);
	$serialized .= $script;

	$serialized .= pack 'V', $self->sequence_number;

	return $serialized;
}

sub from_serialized
{
}

1;

