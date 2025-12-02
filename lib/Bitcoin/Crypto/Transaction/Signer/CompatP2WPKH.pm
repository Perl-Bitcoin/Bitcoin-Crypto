package Bitcoin::Crypto::Transaction::Signer::CompatP2WPKH;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Script::Common;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

extends 'Bitcoin::Crypto::Transaction::Signer::CompatSegwit';

has extended 'script' => (
	writer => 1,
	init_arg => undef,
	lazy => 1,
);

with 'Bitcoin::Crypto::Transaction::Signer::Role::KeyHash';

sub _build_script
{
	Bitcoin::Crypto::Exception::Sign->raise(
		'Compat P2WPKH script cannot be built - use add_signature with a proper private key'
	);
}

before '_add_pkh' => sub {
	my ($self, $privkey) = @_;

	my $pubkey = $privkey->get_public_key;
	$self->set_script(Bitcoin::Crypto::Script::Common->new(PKH => $pubkey->get_hash));
	$self->set_witness_program($pubkey->witness_program);
};

1;

