package Bitcoin::Crypto::Transaction::UTXO;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;

use Bitcoin::Crypto::Transaction;
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Util::Internal qw(to_format);
use Bitcoin::Crypto::Exception;

my %utxos;
my $loader;

has param 'txid' => (
	coerce => ByteStrLen [32],
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

sub register
{
	my ($self) = @_;

	# Do not store NULLDATA UTXOs
	return $self
		if $self->output->is_standard && $self->output->locking_script->type eq 'NULLDATA';

	$utxos{$self->txid . $self->output_index} = $self;
	return $self;
}

sub unregister
{
	my ($self) = @_;

	delete $utxos{$self->txid . $self->output_index};
	return $self;
}

signature_for get => (
	method => !!1,
	positional => [ByteStr, PositiveOrZeroInt],
);

sub get
{
	my ($class, $txid, $outid) = @_;

	my $utxo = $utxos{$txid . $outid};

	if (!$utxo) {

		$utxo = $loader->($txid, $outid)
			if defined $loader;

		Bitcoin::Crypto::Exception::UTXO->raise(
			sprintf(
				"no UTXO registered for transaction id %s and output index %s",
				to_format [hex => $txid],
				$outid
			)
		) unless $utxo;

		$utxo->register;
	}

	return $utxo;
}

signature_for set_loader => (
	method => !!1,
	positional => [Maybe [CodeRef]],
);

sub set_loader
{
	$loader = pop;
	return;
}

sub unload
{
	my @result = values %utxos;
	%utxos = ();

	return \@result;
}

sub registered_count
{
	return scalar keys %utxos;
}

signature_for extract => (
	method => !!1,
	positional => [ByteStr],
);

sub extract
{
	my ($class, $serialized_tx) = @_;

	my $tx = Bitcoin::Crypto::Transaction->from_serialized($serialized_tx);
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
inputs must be UTXOs. You need to register UTXOs before you can fully utilize a
transaction. If a transaction has its UTXOs unregistered, its methods may raise
an exception if they require full UTXO data.

This module keeps an internal register of all valid UTXOs. You can add or
remove UTXOs from this register, and they are accessed using two
characteristics: transaction ID and output number (counted from 0).

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

	$utxo = $class->new(%args)

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

	$utxo = $class->get($txid, $output_index);

Returns the UTXO registered with given txid and output index. Throws an
exception if it cannot be found or loaded.

=head3 set_loader

	$class->set_loader(sub { ... })
	$class->set_loader(undef)

Replaces an UTXO loader.

The subroutine should accept the same parameters as L</get> and return a
constructed UTXO object. If possible, the loader should not return the same
UTXO twice in a single runtime of the script. It will be not informed of UTXOs
being spent, so it should "hand over" UTXOs while marking them as spent in its
source.

Returns nothing. Passing undef disables the custom loader.

=head3 unload

	\@utxos = $class->unload()

Removes all UTXOs from the perl memory and returns them as an array reference.
Returned UTXOs will no longer be visible to L</get> calls.

This may be useful to move the UTXOs gathered in Perl memory to some other
medium, for example a database. L</set_loader> could be set to load UTXOs from
a database, and the script could periodically clear them from its memory to store
them in a persistent storage for later.

=head3 registered_count

	$count = $class->registered_count()

Returns the number of UTXOS currently present in internal perl memory. This can
be used to decide whether a call to L</unload> is needed or not.

=head3 extract

	$class->extract($serialized_tx)

Extracts all outputs from the C<$serialized_tx> (a bytestring). Same can be
achieved by calling C<update_utxos> on a transaction object.

Returns nothing. All C<$serialized_tx> outputs will be added to the register as
new UTXO instances.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

