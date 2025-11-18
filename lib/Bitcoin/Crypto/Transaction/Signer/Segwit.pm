package Bitcoin::Crypto::Transaction::Signer::Segwit;

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

extends 'Bitcoin::Crypto::Transaction::Signer::Legacy';

sub _finalize
{
	my ($self) = @_;

	$self->transaction->inputs->[$self->signing_index]->set_witness(
		[reverse @{$self->_signature}]
	);
}

1;

