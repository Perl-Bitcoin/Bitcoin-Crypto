package Bitcoin::Crypto::Transaction::Output;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Types qw(Int ByteStr InstanceOf);
use Bitcoin::Crypto::Helpers qw(pack_varint ensure_length); # loads BigInt

has param 'value' => (
	coerce => (InstanceOf['Math::BigInt'])
		->where(q{$_ > 0})
		->plus_coercions(Int, q{ Math::BigInt->new($_) }),
);

has param 'locking_script' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Script'])
		->plus_coercions(ByteStr, q{ Bitcoin::Crypto::Script->from_serialized($_) }),
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
	my $value = reverse $self->value->as_bytes;
	$serialized .= ensure_length($value, 8);

	my $script = $self->locking_script->get_script;
	$serialized .= pack_varint(length $script);
	$serialized .= $script;

	return $serialized;
}

sub from_serialized
{
}

1;

