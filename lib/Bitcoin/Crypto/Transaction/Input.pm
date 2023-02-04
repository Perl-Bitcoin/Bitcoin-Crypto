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
	isa => ByteStr,
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

	# input should be as follows:
	# - transaction hash, 32 bytes
	# - transaction output index, 4 bytes
	# - signature script length, 1-9 bytes
	# - signature script
	# - sequence number, 4 bytes
	my $input = '';

	$input .= $self->transaction_hash;

	$input .= pack 'V', $self->transaction_output_index;

	my $script = $self->signature_script->get_script;
	$input .= pack_varint(length $script);
	$input .= $script;

	$input .= pack 'V', $self->sequence_number;

	return $input;
}

sub from_serialized
{
}

1;

