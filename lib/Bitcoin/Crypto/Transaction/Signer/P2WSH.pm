package Bitcoin::Crypto::Transaction::Signer::P2WSH;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

extends 'Bitcoin::Crypto::Transaction::Signer::Segwit';

sub _initialize
{
	my ($self) = @_;

	# do not use add_bytes (not part of this script)
	push @{$self->_signature}, $self->script->to_serialized;
}

1;

