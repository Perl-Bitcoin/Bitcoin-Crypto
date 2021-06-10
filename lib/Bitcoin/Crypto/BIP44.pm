package Bitcoin::Crypto::BIP44;

our $VERSION = "0.996";

use v5.10;
use warnings;
use Moo;
use Types::Standard qw(Enum);
use Types::Common::Numeric qw(PositiveOrZeroInt);
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Exception;

use namespace::clean;

has 'coin_type' => (
	is => 'ro',
	isa => PositiveOrZeroInt,
	coerce => sub {
		my ($coin_type) = @_;

		if (blessed $coin_type) {
			$coin_type = $coin_type->network
				if $coin_type->DOES('Bitcoin::Crypto::Role::Network');

			$coin_type = $coin_type->bip44_coin
				if $coin_type->isa('Bitcoin::Crypto::Network');

			Bitcoin::Crypto::Exception::NetworkConfig->raise(
				"no bip44 coin constant found in network configuration"
			) unless defined $coin_type;
		}
		return $coin_type;
	},
	required => 1,
);

has 'account' => (
	is => 'ro',
	isa => PositiveOrZeroInt,
	default => sub { 0 },
);

has 'change' => (
	is => 'ro',
	isa => Enum[1, 0],
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
	# purpose is always 44 in bip44
	return sprintf "m/44'/%u'/%u'/%u/%u",
		$self->coin_type, $self->account, $self->change, $self->index;
}

1;
