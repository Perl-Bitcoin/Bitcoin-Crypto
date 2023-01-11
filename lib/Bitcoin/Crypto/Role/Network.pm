package Bitcoin::Crypto::Role::Network;

use v5.10;
use strict;
use warnings;
use Scalar::Util qw(blessed);
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Types qw(InstanceOf Str);
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Exception;
use Moo::Role;

has param "network" => (
	coerce => (InstanceOf ["Bitcoin::Crypto::Network"])
		->plus_coercions(Str, q{Bitcoin::Crypto::Network->get($_)}),
	default => sub {
		return Bitcoin::Crypto::Network->get;
	},
	writer => -hidden,
);

# make writer chainable
sub set_network
{
	my ($self, $network) = @_;
	$self->_set_network($network);
	return $self;
}

1;

