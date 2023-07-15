package Bitcoin::Crypto::Transaction::Input;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto qw(btc_utxo);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Helpers qw(pack_varint unpack_varint);
use Bitcoin::Crypto::Types
	qw(ByteStr Str IntMaxBits ArrayRef InstanceOf Object BitcoinScript Bool Defined ScalarRef PositiveOrZeroInt);
use Bitcoin::Crypto::Exception;

has param 'utxo' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Transaction::UTXO'])
		->plus_coercions(ArrayRef, q{ Bitcoin::Crypto::Transaction::UTXO->get(@$_) })
);

has param 'signature_script' => (
	writer => 1,
	coerce => BitcoinScript,
	default => '',
);

has param 'sequence_no' => (
	isa => IntMaxBits [32],
	default => Bitcoin::Crypto::Constants::max_nsequence,
);

has option 'witness' => (
	coerce => ArrayRef [ByteStr],
	writer => 1,
);

signature_for to_serialized => (
	method => Object,
	named => [
		signing => Defined & Bool,
		{optional => 1},
		signing_subscript => ByteStr,
		{optional => 1},
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

	my $transaction_hash = scalar reverse substr $serialized, $pos, 32;
	$pos += 32;

	my $transaction_output_index = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	my ($script_size_len, $script_size) = unpack_varint(substr $serialized, $pos, 9);
	$pos += $script_size_len;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized input script data is corrupted'
	) if $pos + $script_size > length $serialized;

	my $script = substr $serialized, $pos, $script_size;
	$pos += $script_size;

	my $sequence = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized input data is corrupted'
	) if !$partial && $pos != length $serialized;

	${$args->pos} = $pos
		if $partial;

	return $class->new(
		utxo => [$transaction_hash, $transaction_output_index],
		signature_script => $script,
		sequence_no => $sequence,
	);
}

1;

