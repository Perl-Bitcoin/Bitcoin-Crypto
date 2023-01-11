package Bitcoin::Crypto::Role::Compressed;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Types qw(Bool);
use Bitcoin::Crypto::Config;
use Moo::Role;

has param "compressed" => (
	coerce => Bool,
	default => Bitcoin::Crypto::Config::compress_public_point,
	writer => -hidden,
);

sub set_compressed
{
	my ($self, $state) = @_;

	$state = 1
		if @_ == 1;

	$self->_set_compressed($state);
	return $self;
}

1;

