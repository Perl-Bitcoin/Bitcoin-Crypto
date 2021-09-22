package Bitcoin::Crypto::Role::Compressed;

our $VERSION = "1.001";

use v5.10;
use strict;
use warnings;
use Types::Standard qw(Bool);

use Bitcoin::Crypto::Config;
use Moo::Role;

has "compressed" => (
	is => "rw",
	isa => Bool,
	coerce => 1,
	default => Bitcoin::Crypto::Config::compress_public_point,
	writer => "_set_compressed"
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
