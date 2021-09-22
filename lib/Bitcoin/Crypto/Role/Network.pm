package Bitcoin::Crypto::Role::Network;

our $VERSION = "1.002";

use v5.10;
use strict;
use warnings;
use Types::Standard qw(InstanceOf Str);
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Exception;
use Moo::Role;

has "network" => (
	is => "ro",
	isa => (InstanceOf ["Bitcoin::Crypto::Network"])
		->plus_coercions(Str, q{Bitcoin::Crypto::Network->get($_)}),
	default => sub {
		return Bitcoin::Crypto::Network->get;
	},
	coerce => 1,
	writer => "set_network"
);

1;
