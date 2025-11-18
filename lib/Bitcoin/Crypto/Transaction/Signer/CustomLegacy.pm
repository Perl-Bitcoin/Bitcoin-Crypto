package Bitcoin::Crypto::Transaction::Signer::CustomLegacy;

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

extends 'Bitcoin::Crypto::Transaction::Signer::Legacy';

has extended 'script' => (
	lazy => 1,
	init_arg => undef,
);

sub _build_script
{
	my ($self) = @_;

	return $self->transaction->inputs->[$self->signing_index]->utxo->output->locking_script;
}

1;

