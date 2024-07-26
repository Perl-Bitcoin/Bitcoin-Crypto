package Bitcoin::Crypto::Role::Network;

use v5.10;
use strict;
use warnings;
use Scalar::Util qw(blessed);
use Mooish::AttributeBuilder -standard;
use Types::Common -types;

use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Exception;
use Moo::Role;

has param 'network' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Network'])
		->plus_coercions(Str, q{Bitcoin::Crypto::Network->get($_)}),
	default => sub {
		return Bitcoin::Crypto::Network->get;
	},
	writer => -hidden,
	trigger => -hidden,
);

sub _trigger_network
{
	my ($self) = @_;

	if (Bitcoin::Crypto::Network->single_network) {
		my $default = Bitcoin::Crypto::Network->get;
		Bitcoin::Crypto::Exception::NetworkCheck->raise(
			'invalid network, running in single-network mode with ' . $default->id
		) if $default->id ne $self->network->id;
	}
}

# make writer chainable
sub set_network
{
	my ($self, $network) = @_;
	$self->_set_network($network);
	return $self;
}

1;

