package Bitcoin::Crypto::Transaction::Input;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto qw(btc_utxo btc_script);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Helpers qw(pack_varint unpack_varint);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Types
	qw(ByteStr Str IntMaxBits ArrayRef InstanceOf Object BitcoinScript Bool Defined ScalarRef PositiveOrZeroInt);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Script::Common;

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
	writer => 1,
	default => Bitcoin::Crypto::Constants::max_sequence_no,
);

has option 'witness' => (
	coerce => ArrayRef [ByteStr],
	writer => 1,
);

with qw(
	Bitcoin::Crypto::Role::ShallowClone
);

sub _nested_script
{
	my ($self) = @_;

	my $input_script = $self->signature_script->to_serialized;
	return undef unless length $input_script;

	my $push = substr $input_script, 0, 1, '';
	return undef unless ord $push == length $input_script;

	my $real_script = btc_script->from_serialized($input_script);
	return $real_script;
}

# script code for segwit digests (see script_base)
sub _script_code
{
	my ($self) = @_;
	my $utxo = $self->utxo;

	my $locking_script = $utxo->output->locking_script;
	my $program;
	my %types = (
		P2WPKH => sub {

			# get script hash from P2WPKH (ignore the first two OPs - version and push)
			my $hash = substr $locking_script->to_serialized, 2;
			$program = Bitcoin::Crypto::Script::Common->new(PKH => $hash);
		},
		P2WSH => sub {

			# TODO: this is not complete, as it does not take OP_CODESEPARATORs into account
			# NOTE: Transaction::Digest sets witness to signing_subscript
			$program = btc_script->from_serialized(($self->witness // [''])->[-1]);
		},
	);

	my $type = $utxo->output->locking_script->type;

	if ($type eq 'P2SH') {

		# nested - nothing should get here without checking if nested script is native segwit
		my $nested = $self->_nested_script;
		$type = $nested->type;

		$locking_script = $nested;
	}

	$types{$type}->();
	return $program;
}

signature_for to_serialized => (
	method => Object,
	positional => [
	],
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

	$serialized .= $self->prevout;

	my $script = $self->signature_script->to_serialized;
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

signature_for is_segwit => (
	method => Object,
	positional => [],
);

sub is_segwit
{
	my ($self) = @_;

	# Determines whether this script is segwit (including nested variants).
	# There's no need to verify P2SH hash matching, as it will be checked at a
	# later stage. It's enough if the input promises the segwit format.

	my $output_script = $self->utxo->output->locking_script;
	return !!1 if $output_script->is_native_segwit;
	return !!0 unless ($output_script->type // '') eq 'P2SH';

	my $nested = $self->_nested_script;
	return !!0 unless defined $nested;
	return !!1 if $nested->is_native_segwit;

	return !!0;
}

signature_for prevout => (
	method => Object,
	positional => [],
);

sub prevout
{
	my ($self) = @_;
	my $utxo = $self->utxo;

	return scalar reverse($utxo->txid) . pack 'V', $utxo->output_index;
}

signature_for script_base => (
	method => Object,
	positional => [],
);

sub script_base
{
	my ($self) = @_;

	if ($self->is_segwit) {

		# no need to check for standard, as segwit is already standard
		return $self->_script_code;
	}
	else {
		return $self->utxo->output->locking_script;
	}
}

signature_for dump => (
	method => Object,
	named => [
	],
);

sub dump
{
	my ($self, $params) = @_;

	my $type = $self->utxo->output->locking_script->type // 'Custom';
	my $address = $self->utxo->output->locking_script->get_address;
	$address = " from $address" if $address;

	my @result;
	push @result, "$type Input$address";
	push @result, 'spending output #' . $self->utxo->output_index . ' from ' . to_format([hex => $self->utxo->txid]);
	push @result, 'value: ' . $self->utxo->output->value;
	push @result, sprintf 'sequence: 0x%X', $self->sequence_no;
	push @result, 'locking script: ' . to_format [hex => $self->utxo->output->locking_script->to_serialized];

	if (!$self->signature_script->is_empty) {
		push @result, 'signature script: ' . to_format [hex => $self->signature_script->to_serialized];
	}

	if ($self->has_witness) {
		push @result, 'witness: ';
		foreach my $witness (@{$self->witness}) {
			push @result, to_format [hex => $witness];
		}
	}

	return join "\n", @result;
}

1;

