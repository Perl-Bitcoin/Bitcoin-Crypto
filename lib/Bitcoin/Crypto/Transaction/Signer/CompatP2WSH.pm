package Bitcoin::Crypto::Transaction::Signer::CompatP2WSH;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

extends 'Bitcoin::Crypto::Transaction::Signer::CompatSegwit';

sub _initialize
{
	my ($self) = @_;

	# do not use add_bytes (not part of this script)
	push @{$self->_signature}, $self->script->to_serialized;

	# need to do this early so that input will be recognized as segwit
	$self->_replace_signature($self->script->witness_program);
}

1;

