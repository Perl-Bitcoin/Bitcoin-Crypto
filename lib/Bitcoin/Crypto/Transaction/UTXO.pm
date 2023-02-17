package Bitcoin::Crypto::Transaction::UTXO;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Types qw(IntMaxBits Int PositiveOrZeroInt ByteStr InstanceOf HashRef Str Object);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Exception;

my %utxos;

has param 'txid' => (
	coerce => ByteStr->create_child_type(
		constraint => q{ length $_ == 32 },
		coercion => 1
	),
);

has param 'output_index' => (
	isa => IntMaxBits[32],
);

has param 'output' => (
	coerce => (InstanceOf['Bitcoin::Crypto::Transaction::Output'])
		->plus_coercions(HashRef q{ Bitcoin::Crypto::Transaction::Output->new($_) }),
);

signature_for register => (
	method => Object,
	positional => [],
);

sub register
{
	my ($self) = @_;

	$utxos{$self->txid}[$self->output_index] = $self;
	return $self;
}

signature_for get => (
	method => Str,
	positional => [ByteStr, PositiveOrZeroInt],
);

sub get
{
	my ($class, $txid, $outid) = @_;

	Bitcoin::Crypto::Exception::UTXO->raise(
		"no UTXO registered for transaction id @{[to_format [hex => $txid]]} and output index $outid"
	) unless $utxos{$txid}[$outid];

	return $utxos{$txid}[$outid];
}

1;

