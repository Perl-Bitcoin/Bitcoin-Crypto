package Bitcoin::Crypto::Role::Network;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard, -role;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Exception;

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
			sprintf 'invalid network %s, running in single-network mode with %s', $self->network->id, $default->id
		) if $default->id ne $self->network->id;
	}
}

sub set_network
{
	my ($self, $network) = @_;
	$self->_set_network($network);

	# chainable - undocumented behavior, but kept for backcompat
	return $self;
}

1;

