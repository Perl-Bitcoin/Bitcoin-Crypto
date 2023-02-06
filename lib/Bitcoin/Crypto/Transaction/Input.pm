package Bitcoin::Crypto::Transaction::Input;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Helpers qw(pack_varint);
use Bitcoin::Crypto::Types qw(Str IntMaxBits ByteStr InstanceOf);

has param 'transaction_hash' => (
	isa => ByteStr->where(q{ length $_ == 32 }),
);

has param 'transaction_output_index' => (
	isa => IntMaxBits[32],
);

has param 'signature_script' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Script'])
		->plus_coercions(ByteStr, q{ Bitcoin::Crypto::Script->from_serialized($_) }),
);

has param 'sequence_number' => (
	isa => IntMaxBits[32],
	default => 0xffffffff,
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

