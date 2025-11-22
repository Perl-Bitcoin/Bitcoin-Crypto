package Bitcoin::Crypto::Transaction::Signer::P2PKH;

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

extends 'Bitcoin::Crypto::Transaction::Signer::CustomLegacy';

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

	$self->add_bytes($privkey->get_public_key->to_serialized);
	$self->SUPER::add_signature($privkey, $args);

	return $self;
}

1;

