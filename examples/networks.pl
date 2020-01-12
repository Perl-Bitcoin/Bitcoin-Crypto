use Modern::Perl "2010";
use Bitcoin::Crypto::Key::ExtPrivate;
use Bitcoin::Crypto::Network;
use Test::More;

sub check_default_network
{
	my ($pkey) = @_;
	my $default = Bitcoin::Crypto::Network->get;

	return $pkey->network->id eq $default->id;
}

# generate a new mnemonic
my $mnemonic = Bitcoin::Crypto::Key::ExtPrivate->generate_mnemonic;

# this key will be assigned to a default network ...
my $pkey = Bitcoin::Crypto::Key::ExtPrivate->from_mnemonic($mnemonic);
ok check_default_network $pkey;

# ... and its public keys too ...
my $pubkey = $pkey->get_public_key;
ok check_default_network $pubkey;

# ... and its derived keys too ...
my $derived = $pkey->derive_key("m/5'");
ok check_default_network $derived;

# ... and its basic keys too.
my $pkey_basic = $pkey->get_basic_key;
ok check_default_network $pkey_basic;


# however once we change the network ...
$pkey->set_network("bitcoin_testnet");
ok !check_default_network $pkey;

# ... all of these will have it as well after regeneration
# without the need to set the network manually for them
$pubkey = $pkey->get_public_key;
ok !check_default_network $pubkey;

$derived = $pkey->derive_key("m/5'");
ok !check_default_network $derived;

$pkey_basic = $pkey->get_basic_key;
ok !check_default_network $pkey_basic;


# Same private key can be used with different cryptocurrencies,
# although this is usually done with bip44 spec deriviation paths
# (see bip44.pl example)
my $address_testnet = $pkey_basic
	->get_public_key
	->get_segwit_address;

my $address_mainnet = $pkey_basic
	->set_network("bitcoin")
	->get_public_key
	->get_segwit_address;

isnt $address_testnet, $address_mainnet;
note $address_testnet;
note $address_mainnet;

done_testing;
