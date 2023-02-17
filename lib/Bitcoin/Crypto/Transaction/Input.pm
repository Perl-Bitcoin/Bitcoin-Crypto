package Bitcoin::Crypto::Transaction::Input;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Transaction::UTXO;
use Bitcoin::Crypto::Helpers qw(pack_varint);
use Bitcoin::Crypto::Types qw(IntMaxBits ArrayRef InstanceOf Object BitcoinScript Bool Defined);

has param 'utxo' => (
	coerce => (InstanceOf['Bitcoin::Crypto::Transaction::UTXO'])
		->plus_coercions(ArrayRef, q{ Bitcoin::Crypto::Transaction::UTXO->get(@$_) })
);

has param 'signature_script' => (
	writer => 1,
	coerce => BitcoinScript,
);

has param 'sequence_no' => (
	isa => IntMaxBits[32],
	default => 0xffffffff,
);

signature_for to_serialized => (
	method => Object,
	named => [for_signing => Defined & Bool, { optional => 1 }],
	named_to_list => 1,
);

sub to_serialized
{
	my ($self, $for_signing) = @_;

	# input should be serialized as follows:
	# - transaction hash, 32 bytes
	# - transaction output index, 4 bytes
	# - signature script length, 1-9 bytes
	# - signature script
	# - sequence number, 4 bytes
	my $serialized = '';

	my $utxo = $self->utxo;
	$serialized .= scalar reverse $utxo->txid;
	$serialized .= pack 'V', $utxo->output_index;

	my $script = defined $for_signing
		? $for_signing
			? $utxo->output->locking_script->to_serialized
			: "\x00"
		: $self->signature_script->to_serialized;

	$serialized .= pack_varint(length $script);
	$serialized .= $script;

	$serialized .= pack 'V', $self->sequence_no;

	return $serialized;
}

sub from_serialized
{
}

1;

