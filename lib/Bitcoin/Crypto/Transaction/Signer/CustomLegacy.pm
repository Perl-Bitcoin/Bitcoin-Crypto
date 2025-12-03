package Bitcoin::Crypto::Transaction::Signer::CustomLegacy;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

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

