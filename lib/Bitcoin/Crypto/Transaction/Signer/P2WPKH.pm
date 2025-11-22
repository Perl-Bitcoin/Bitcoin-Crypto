package Bitcoin::Crypto::Transaction::Signer::P2WPKH;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Script::Common;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

extends 'Bitcoin::Crypto::Transaction::Signer::Segwit';

has extended 'script' => (
	lazy => 1,
	init_arg => undef,
);

with 'Bitcoin::Crypto::Transaction::Signer::Role::KeyHash';

sub _build_script
{
	my ($self) = @_;

	my $script = $self->transaction->inputs->[$self->signing_index]->utxo->output->locking_script;
	my $runner = $script->run;
	my ($version, $pkh) = @{$runner->stack};

	return Bitcoin::Crypto::Script::Common->new(PKH => $pkh);
}

1;

