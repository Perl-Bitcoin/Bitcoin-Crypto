package Bitcoin::Crypto::Transaction::Signer::CompatP2WPKH;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto::Script::Common;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

extends 'Bitcoin::Crypto::Transaction::Signer::CompatSegwit';

has extended 'script' => (
	writer => 1,
	init_arg => undef,
	lazy => 1,
);

sub _build_script
{
	Bitcoin::Crypto::Exception::Sign->raise(
		'Compat P2WPKH script cannot be built - use add_signature with a proper private key'
	);
}

signature_for add_signature => (
	method => Object,
	head => [InstanceOf ['Bitcoin::Crypto::Key::Private']],
	named => [
		sighash => Maybe [PositiveOrZeroInt],
		{default => undef},
	],
	bless => !!0,
);

sub add_signature
{
	my ($self, $privkey, $args) = @_;

	my $pubkey = $privkey->get_public_key;
	$self->set_script(Bitcoin::Crypto::Script::Common->new(PKH => $pubkey->get_hash));
	$self->set_witness_program($pubkey->witness_program);

	$self->add_bytes($pubkey->to_serialized);
	$self->SUPER::add_signature($privkey, $args);

	return $self;
}

1;

