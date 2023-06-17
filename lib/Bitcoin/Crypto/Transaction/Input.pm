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
use Bitcoin::Crypto::Types qw(ByteStr IntMaxBits ArrayRef InstanceOf Object BitcoinScript Bool Defined);

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
	named => [
		signing => Defined & Bool, { optional => 1 },
		signing_subscript => ByteStr, { optional => 1 },
	],
);

sub to_serialized
{
	my ($self, $args) = @_;

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

	my $script;
	if (defined $args->signing) {
		if ($args->signing) {
			$script = $args->signing_subscript;
			$script //= $utxo->output->locking_script->to_serialized
				if $utxo->output->is_standard;

			Bitcoin::Crypto::Exception::Transaction->raise(
				"can't guess the subscript from a non-standard transaction"
			) unless defined $script;
		}
		else {
			$script //= "\x00";
		}
	}
	else {
		$script = $self->signature_script->to_serialized;
	}

	$serialized .= pack_varint(length $script);
	$serialized .= $script;

	$serialized .= pack 'V', $self->sequence_no;

	return $serialized;
}

sub from_serialized
{
}

1;

