use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use Bitcoin::Crypto::Config;
use Encode qw(encode);
use utf8;

BEGIN { use_ok('Bitcoin::Crypto::Key::Private') }

my %cases = qw(
	641ce7ab9a2ec7697f32d3ade425d9785e8f23bea3501524852cda3ca05fae28
	04394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967c52ad62fe0b27e5acc0992fc8509e5041a06064ce967200b0b7288a4ab889bf22
	b7331fd4ff8c53d31fa7d1625df7de451e55dc53337db64bee3efadb7fdd28d9
	043992aa3f9deda22c02d05ca01a55d8f717d7464bb11ef43b59fc36c32613d0205f34f4ef398da815711d8917b804d429f395af403d52cd4b65b76839c88da442
);

my $PrivateKey = "Bitcoin::Crypto::Key::Private";

# silence warnings
local $SIG{__WARN__} = sub { };

# Basic creation of public keys - 4 tests
for my $key (keys %cases) {
	my $privkey = $PrivateKey->from_hex($key)->set_compressed(0);
	is($privkey->to_hex(), $key, "imported and exported correctly");
	is($privkey->get_public_key()->to_hex(), $cases{$key}, "correctly created public key");
}

my @keylist = keys %cases;
my $privkey = $PrivateKey->from_hex($keylist[0])->set_compressed(0);
my $pubkey = $privkey->get_public_key();

# Message signing
my @messages = ("Perl test script", "", "a", "_ś\x1f " x 250);
for my $message (@messages) {
	$message = encode('UTF-8', $message);
	my $signature = $privkey->sign_message($message);

	# ok($privkey->sign_message($message) eq $signature, "Signatures generation should be deterministic")
	# 	or diag("Signatures generation seems to be nondeterministic, which is a possible private key security threat");

	ok($privkey->verify_message($message, $signature), "Valid signature");
	ok($pubkey->verify_message($message, $signature), "Pubkey recognizes signature");

	my $privkey2 = $PrivateKey->from_hex($keylist[1]);
	my $pubkey2 = $privkey2->get_public_key();

	ok(
		!$pubkey2->verify_message($message, $signature),
		"Different pubkey doesn't recognize signature"
	);
}

# WIF import / export - 4 tests
my $wif_raw_key = "972e85e7e3345cb7e6a5f812aa5f5bea82005e3ded7b32d9d56f5ab2504f1648";
my $wif = "5JxsKGzCoJwaWEjQvfNqD4qPEoUQ696BUEq68Y68WQ2GNR6zrxW";
my $testnet_wif = "92jVu1okPY1iUJEhZ1Gk5fPLtTq7FJdNpBh3DASdr8mK9SZXqy3";
is($PrivateKey->from_wif($wif)->to_hex(), $wif_raw_key, "imported WIF correctly");
is(
	$PrivateKey->from_hex($wif_raw_key)->set_compressed(0)->to_wif(), $wif,
	"exported WIF correctly"
);
is(
	$PrivateKey->from_wif($testnet_wif)->network->name,
	"Bitcoin Testnet",
	"Recognized non-default network"
);
is(
	$PrivateKey->from_wif($testnet_wif)->to_hex(),
	$wif_raw_key, "imported non-default network WIF correctly"
);
is(
	$PrivateKey->from_wif($testnet_wif)->get_public_key()->network->name,
	"Bitcoin Testnet",
	"Passed network to public key"
);

# Key length testing - 3 tests
my $short_key = "e8d964843cc55a91d";
my $longer_key = "d0a08067d186ffd9d14e8d964843cc55a91d";
my $too_long_key = "a3bc641ce7ab9a2ec7697f32d3ade425d9785e8f23bea3501524852cda3ca05fae28";

is(
	length $PrivateKey->from_hex($short_key)->to_bytes(),
	Bitcoin::Crypto::Config::key_max_length, "Short key length OK"
);
is(
	length $PrivateKey->from_hex($longer_key)->to_bytes(),
	Bitcoin::Crypto::Config::key_max_length, "Longer key length OK"
);

throws_ok {
	$PrivateKey->from_hex($too_long_key);
}
"Bitcoin::Crypto::Exception::KeyCreate", "Too long key got rejected";

done_testing;
