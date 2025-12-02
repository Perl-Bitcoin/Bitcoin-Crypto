package Bitcoin::Crypto::Transaction::Signer::CompatP2WSH;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

extends 'Bitcoin::Crypto::Transaction::Signer::CompatSegwit';

sub _initialize
{
	my ($self) = @_;

	# do not use add_bytes (not part of this script)
	push @{$self->_signature}, $self->script->to_serialized;

	$self->set_witness_program($self->script->witness_program);
}

1;

