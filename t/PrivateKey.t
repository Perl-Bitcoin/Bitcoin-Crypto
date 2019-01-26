use strict;
use warnings;

use Test::More tests => 19;
use Try::Tiny;
use Bitcoin::Crypto::Config;

BEGIN { use_ok('Bitcoin::Crypto::PrivateKey') };

my %cases = qw(
    641ce7ab9a2ec7697f32d3ade425d9785e8f23bea3501524852cda3ca05fae28
    04394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967c52ad62fe0b27e5acc0992fc8509e5041a06064ce967200b0b7288a4ab889bf22
    b7331fd4ff8c53d31fa7d1625df7de451e55dc53337db64bee3efadb7fdd28d9
    043992aa3f9deda22c02d05ca01a55d8f717d7464bb11ef43b59fc36c32613d0205f34f4ef398da815711d8917b804d429f395af403d52cd4b65b76839c88da442
);

my $PrivateKey = "Bitcoin::Crypto::PrivateKey";

# Basic creation of public keys - 4 tests
for my $key (keys %cases) {
    my $privkey = $PrivateKey->fromHex($key)->setCompressed(0);
    is($privkey->toHex(), $key, "imported and exported correctly");
    is($privkey->getPublicKey()->toHex(), $cases{$key}, "correctly created public key");
}

my @keylist = keys %cases;
my $privkey = $PrivateKey->fromHex($keylist[0])->setCompressed(0);
my $pubkey = $privkey->getPublicKey();

# Message signing - 3 tests
my $message = "Perl test script";
my $signature = $privkey->signMessage($message);

ok($privkey->signMessage($message) eq $signature, "Signatures generation should be deterministic")
    or diag("Signatures generation seems to be nondeterministic, which is a possible private key security threat");

ok($privkey->verifyMessage($message, $signature), "Valid signature");
ok($pubkey->verifyMessage($message, $signature), "Pubkey recognizes signature");

my $privkey2 = $PrivateKey->fromHex($keylist[1]);
my $pubkey2 = $privkey2->getPublicKey();

ok(!$pubkey2->verifyMessage($message, $signature), "Different pubkey doesn't recognize signature");

# WIF import / export - 4 tests
my $wif_raw_key = "972e85e7e3345cb7e6a5f812aa5f5bea82005e3ded7b32d9d56f5ab2504f1648";
my $wif = "5JxsKGzCoJwaWEjQvfNqD4qPEoUQ696BUEq68Y68WQ2GNR6zrxW";
my $testnet_wif = "92jVu1okPY1iUJEhZ1Gk5fPLtTq7FJdNpBh3DASdr8mK9SZXqy3";

is($PrivateKey->fromWif($wif)->toHex(), $wif_raw_key, "imported WIF correctly");
is($PrivateKey->fromHex($wif_raw_key)->setCompressed(0)->toWif(), $wif, "exported WIF correctly");
is($PrivateKey->fromWif($testnet_wif)->network->{name}, "Bitcoin Testnet", "Recognized non-default network");
is($PrivateKey->fromWif($testnet_wif)->toHex(), $wif_raw_key, "imported non-default network WIF correctly");
is($PrivateKey->fromWif($testnet_wif)->getPublicKey()->network->{name}, "Bitcoin Testnet", "Passed network to public key");

# Mnemonic import / export - 2 tests
my $mnemonic_raw_key = "b792d0a08067d186ffd9d14e8d964843cc55a91d";
my $mnemonic = "resource notable choice absorb laptop sell youth demand excess hole must maple shed stand item";

is($PrivateKey->fromBip39Mnemonic($mnemonic)->toHex(), $mnemonic_raw_key, "imported mnemonic correctly");
is($PrivateKey->fromHex($mnemonic_raw_key)->toBip39Mnemonic(), $mnemonic, "exported mnemonic correctly");

# Key length testing - 3 tests
my $short_key = "e8d964843cc55a91d";
my $longer_key = "d0a08067d186ffd9d14e8d964843cc55a91d";
my $too_long_key = "a3bc641ce7ab9a2ec7697f32d3ade425d9785e8f23bea3501524852cda3ca05fae28";

is(length $PrivateKey->fromHex($short_key)->toBytes(), $config{key_min_length}, "Short key length OK");
is((length($PrivateKey->fromHex($longer_key)->toBytes()) - $config{key_min_length}) % $config{key_length_step}, 0, "Longer key length OK");

try {
    $PrivateKey->fromHex($too_long_key);
    fail("Too long key was accepted");
} catch {
    if (m/[0-9]+ bytes/) {
        pass("Too long key got rejected");
    } else {
        fail("Too long key failed with unknown reason");
    }
};
