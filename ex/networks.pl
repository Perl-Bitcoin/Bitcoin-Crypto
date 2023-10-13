use v5.10;
use strict;
use warnings;
use Bitcoin::Crypto::Key::ExtPrivate;
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Util qw(generate_mnemonic);

my $mnemonic = generate_mnemonic;

# this key will be assigned to a default network, as well as
# any other keys acquired using it
my $pkey = Bitcoin::Crypto::Key::ExtPrivate->from_mnemonic($mnemonic);
my $pubkey = $pkey->get_public_key;
my $derived = $pkey->derive_key("m/5'");
my $pkey_basic = $pkey->get_basic_key;

# however once we change the network ...
$pkey->set_network("bitcoin_testnet");

# ... all of these will have to be regenerated to also have it
$pubkey = $pkey->get_public_key;
$derived = $pkey->derive_key("m/5'");
$pkey_basic = $pkey->get_basic_key;

# Same private key can be used with different cryptocurrencies,
# although this is usually done with bip44 spec derivation paths
# (see bip44.pl example)
my $address_testnet = $pkey_basic
	->get_public_key
	->get_segwit_address;

my $address_mainnet = $pkey_basic
	->set_network("bitcoin")
	->get_public_key
	->get_segwit_address;

__END__

=head1 Network usage example

This example is a step-by-step usage example of the network system from the
perspective of an user (with networks already registered). Provided test cases
explain how the network is propagated through an usual chain of element
generation (extended key -> basic key, private key -> public key).

See inline comments for explanations of the test cases provided.

