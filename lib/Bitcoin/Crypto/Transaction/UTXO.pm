package Bitcoin::Crypto::Transaction::UTXO;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Types qw(IntMaxBits Int PositiveOrZeroInt ByteStr InstanceOf HashRef Str Object CodeRef);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Exception;

my %utxos;
my $loader;

has param 'txid' => (
	coerce => ByteStr->create_child_type(
		constraint => q{ length $_ == 32 },
		coercion => 1
	),
);

# TODO: ideally, utxo should point to a transaction, and transaction should
# point to a block
has option 'block' => (
	isa => InstanceOf ['Bitcoin::Crypto::Block'],
);

has param 'output_index' => (
	isa => IntMaxBits [32],
);

has param 'output' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Transaction::Output'])
		->plus_coercions(HashRef q{ Bitcoin::Crypto::Transaction::Output->new($_) }),
);

signature_for register => (
	method => Object,
	positional => [],
);

sub register
{
	my ($self) = @_;

	# Do not store NULLDATA UTXOs
	return $self
		if $self->output->is_standard && $self->output->locking_script->type eq 'NULLDATA';

	$utxos{$self->txid}[$self->output_index] = $self;
	return $self;
}

signature_for unregister => (
	method => Object,
	positional => [],
);

sub unregister
{
	my ($self) = @_;

	delete $utxos{$self->txid}[$self->output_index];
	return $self;
}

signature_for get => (
	method => Str,
	positional => [ByteStr, PositiveOrZeroInt],
);

sub get
{
	my ($class, $txid, $outid) = @_;

	my $utxo = $utxos{$txid}[$outid];

	# NOTE: loader should unregister the utxo in its own store
	if (!$utxo && defined $loader) {
		$utxo = $loader->($txid, $outid);
		$utxo->register if $utxo;
	}

	Bitcoin::Crypto::Exception::UTXO->raise(
		"no UTXO registered for transaction id @{[to_format [hex => $txid]]} and output index $outid"
	) unless $utxo;

	return $utxo;
}

signature_for set_loader => (
	method => Str,
	positional => [CodeRef],
);

sub set_loader
{
	my ($class, $new_loader) = @_;

	$loader = $new_loader;
	return;
}

1;

