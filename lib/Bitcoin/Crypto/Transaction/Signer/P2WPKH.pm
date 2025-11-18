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

sub _build_script
{
	my ($self) = @_;

	my $script = $self->transaction->inputs->[$self->signing_index]->utxo->output->locking_script;
	my $runner = $script->run;
	my ($version, $pkh) = @{$runner->stack};

	return Bitcoin::Crypto::Script::Common->new(PKH => $pkh);
}

signature_for add_signature => (
	method => Object,
	head => [InstanceOf ['Bitcoin::Crypto::Key::Private']],
	named => [
		sighash => Optional [PositiveOrZeroInt],
	],
	bless => !!0,
);

sub add_signature
{
	my ($self, $privkey, $args) = @_;

	$self->add_bytes($privkey->get_public_key->to_serialized);
	$self->SUPER::add_signature($privkey, $args);

	return $self;
}

1;

