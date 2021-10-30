package Bitcoin::Crypto::BIP44;

our $VERSION = "1.004";

use v5.10;
use strict;
use warnings;
use Moo;
use Types::Standard qw(Enum);
use Types::Common::Numeric qw(PositiveOrZeroInt);
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Exception;

sub _get_network_constant
{
	my ($network) = @_;

	my $coin_type = $network->bip44_coin;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"no bip44_coin constant found in network configuration"
	) unless defined $coin_type;

	return $coin_type;
}

use namespace::clean;

has 'purpose' => (
	is => 'ro',
	isa => Enum[44, 49, 84],
	default => sub { 44 },
);

has 'coin_type' => (
	is => 'ro',
	isa => PositiveOrZeroInt,
	coerce => sub {
		my ($coin_type) = @_;

		if (blessed $coin_type) {
			$coin_type = $coin_type->network
				if $coin_type->DOES('Bitcoin::Crypto::Role::Network');

			$coin_type = _get_network_constant($coin_type)
				if $coin_type->isa('Bitcoin::Crypto::Network');
		}

		return $coin_type;
	},
	default => sub {
		_get_network_constant(Bitcoin::Crypto::Network->get);
	},
);

has 'account' => (
	is => 'ro',
	isa => PositiveOrZeroInt,
	default => sub { 0 },
);

has 'change' => (
	is => 'ro',
	isa => Enum [1, 0],
	default => sub { 0 },
);

has 'index' => (
	is => 'ro',
	isa => PositiveOrZeroInt,
	required => 1,
);

use overload
	q{""} => "as_string",
	fallback => 1;

sub as_string
{
	my ($self) = @_;

	# https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
	# m / purpose' / coin_type' / account' / change / address_index
	return sprintf "m/%u'/%u'/%u'/%u/%u",
		$self->purpose, $self->coin_type, $self->account, $self->change, $self->index;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::BIP44 - BIP44 implementation in Perl

=head1 SYNOPSIS

	use Bitcoin::Crypto::BIP44;

	my $path = Bitcoin::Crypto::BIP44->new(
		coin_type => Bitcoin::Crypto::Network->get('bitcoin_testnet'), # can also be a number or a key instance
		index => 43,
		# account => 0,
		# change => 0,
	);

	# stringifies automatically
	say "$path";

	# can be used in key derivation
	$ext_private_key->derive_key($path);

=head1 DESCRIPTION

This class is a helper for constructing BIP44-compilant key derivation paths. BIP44 describes the mechanism the HD (Hierarchical Deterministic) wallets use to decide derivation paths for coins. BIP49 and BIP84 are constructed the same way, but used for compat and segwit addresses respectively.

Each coin has its own C<coin_type> constant, a list of which is maintained here: L<https://github.com/satoshilabs/slips/blob/master/slip-0044.md>. L<Bitcoin::Crypto::Network> instances hold these constants under the C<bip44_coin> property.

BIP44 objects stringify automatically and can be directly used in L<Bitcoin::Crypto::Key::ExtPrivate/derive_key> method. In return, any key object can be used as C<coin_type> in L</new>, which will automatically fetch coin_type number from the key's current network.

=head1 PROPERTIES

Refer to L<https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki> for details of those properties.

All of these properties can be fetched using a method with the same name.

=head2 purpose

Purpose contains the BIP document number that you wish to use. Can be either C<44>, C<49> or C<84>.

By default, number C<44> will be used.

=head2 coin_type

Needs to be a non-negative integer number. It should be less than C<2^31> (but will not check for that).

Will also accept key objects and network objects, as it is possible to fetch the constant for them. In this case, it might raise an exception if the network does not contain the C<bip44_coin> constant.

This value should be in line with the table of BIP44 constants mentioned above.

By default, the value defined in the current default network will be used: see L<Bitcoin::Crypto::Network>.

=head2 account

Needs to be a non-negative integer number. It should be less than C<2^31> (but will not check for that).

By default, the value C<0> is used.

=head2 change

Needs to be a number C<1> (for addresses to be used as change outputs) or C<0> (for addresses that are to be used only internally).
By default, the value C<0> is used.

=head2 index

Required. Needs to be a non-negative integer number. It should be less than C<2^31> (but will not check for that).

=head1 METHODS

=head2 new

	$key_object = $class->new(%data)

This is a regular Moo constructor, which can be used to create the object. It takes arguments specified in L</PROPERTIES>.

Returns class instance.

=head2 as_string

	$path = $object->as_string()

Stringifies the object as BIP44-compilant key derivation path. Can be used indirectly by just stringifying the object.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=item L<Bitcoin::Crypto::Network>

=back

=cut
