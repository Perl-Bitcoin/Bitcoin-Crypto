package Bitcoin::Crypto::Transaction::Signer::CompatSegwit;

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

sub _replace_signature
{
	my ($self, $witness_program) = @_;

	$self->transaction->inputs->[$self->signing_index]->set_signature_script(
		btc_script->new->push_bytes($witness_program->to_serialized)
	);
}

sub _finalize
{
	my ($self) = @_;

	$self->SUPER::_finalize;
}

1;

