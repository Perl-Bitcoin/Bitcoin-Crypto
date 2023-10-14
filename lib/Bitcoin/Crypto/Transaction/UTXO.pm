package Bitcoin::Crypto::Transaction::UTXO;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Transaction;
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Types qw(IntMaxBits Int PositiveOrZeroInt ByteStr InstanceOf HashRef Str Object Maybe CodeRef);
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

# NOTE: ideally, utxo should point to a transaction, and transaction should
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
	positional => [Maybe[CodeRef]],
);

sub set_loader
{
	my ($class, $new_loader) = @_;

	$loader = $new_loader;
	return;
}

signature_for extract => (
	method => Str,
	positional => [ByteStr],
);

sub extract
{
	my ($class, $serialized_tx) = @_;

	# hijack the utxo loader
	my $old_loader = $loader;
	$loader = sub {
		if ($old_loader) {
			my $loaded = $old_loader->(@_);
			return $loaded if $loaded;
		}

		return $class->new(
			txid => shift,
			output_index => shift,
			output => {
				locking_script => [NULLDATA => 'stub utxo'],
				value => 0,
			},
		);
	};

	my $tx = Bitcoin::Crypto::Transaction->from_serialized($serialized_tx);
	$loader = $old_loader;

	$tx->update_utxos;
	return;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Transaction::UTXO - Unspent transaction output instance

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_utxo);

	# register the utxos automatically from the serialized transaction
	btc_utxo->extract($serialized_tx);

	# create the utxo manually
	my $utxo = btc_utxo->new(
		txid => [hex => '94e519b9c0f43228e3dc841d838fc7372de95345206ef936ac6020889abe0457'],
		output_index => 1,
		output => {
			locking_script => [P2PKH => '1HrfeGdVP4d1uAdbSknzeaFpDFQVJyVpLu'],
			value => 1_02119131,
		}
	);

	# register
	$utxo->register;

	# find the utxo
	btc_utxo->get([hex => '94e519b9c0f43228e3dc841d838fc7372de95345206ef936ac6020889abe0457'], 1);

	# unregister
	$utxo->unregister;

=head1 DESCRIPTION

UTXO is a transaction output which hasn't been spent yet. All transaction
inputs must be UTXOs. Bitcoin::Crypto requires you to register UTXOs before you
can create a transaction.

=head1 INTERFACE

=head2 Attributes

=head3 txid

A bytestring - id of the source transaction.

I<Available in the constructor>.

=head3 output_index

A positive or zero integer which is the index of the output in the source
transaction.

I<Available in the constructor>.

=head3 block

Optional instance of L<Bitcoin::Crypto::Block>.

I<Available in the constructor>.

=head3 output

Instance of L<Bitcoin::Crypto::Transaction::Output>. A hash reference will be
coerced into an object by passing it to the constructor.

I<Available in the constructor>.

=head2 Methods

=head3 new

	$tx = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 register

	$object = $object->register()

Registers the given UTXO. It will be held in memory and will be available to
fetch using L</get>.

=head3 unregister

	$object = $object->unregister()

Does the opposite of L</register>.

=head3 get

	$utxo = $object->get($txid, $output_index);

Returns the UTXO registered with given txid and output index. Throws an
exception if it cannot be found or loaded.

=head3 set_loader

	$class->set_loader(sub { ... })
	$class->set_loader(undef)

Replaces an UTXO loader.

The subroutine should accept the same parameters as L</get> and return a
constructed UTXO object. If possible, the loader should not return the same
UTXO twice in a single runtime of the script.

Returns nothing. Passing undef disables the loader.

=head3 extract

	$class->extract($serialized_tx)

Extracts all outputs from the C<$serialized_tx> (a bytestring).

Returns nothing.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * Bitcoin::Crypto::Exception::UTXO - UTXO was not found

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

