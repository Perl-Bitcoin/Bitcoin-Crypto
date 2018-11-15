use strict;
use warnings;

use Test::More tests => 14;
use Bitcoin::Crypto::Util qw(pack_hex validate_address);

BEGIN { use_ok('Bitcoin::Crypto::PublicKey') };

my $PublicKey = "Bitcoin::Crypto::PublicKey";

my %cases = qw(
    04394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967c52ad62fe0b27e5acc0992fc8509e5041a06064ce967200b0b7288a4ab889bf22
    16ixDtpj3JyKJUagRtLdhav76gw1MnrmsK
    043992aa3f9deda22c02d05ca01a55d8f717d7464bb11ef43b59fc36c32613d0205f34f4ef398da815711d8917b804d429f395af403d52cd4b65b76839c88da442
    17MscEiRueoN9psHqV6oQGq8UWtdoaezSq
);

my %cases_compressed = qw(
    02394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967c
    14wc2Jf5WoX1UZuwkb62acVRfNMwczjwDf
    023992aa3f9deda22c02d05ca01a55d8f717d7464bb11ef43b59fc36c32613d020
    16e5qefUVTiLxDuwpNTsJ7b3VL7rSmfYdc
);

# Basic creation of addresses keys - 8 tests
for my $key (keys %cases) {
    my $pubkey = $PublicKey->fromHex($key);
    is($pubkey->toHex(), $key, "imported and exported correctly");
    is($pubkey->getAddress(), $cases{$key}, "correctly created address");
    $pubkey->setCompressed(1);
    ok(defined $cases_compressed{$pubkey->toHex()}, "exported compressed key correctly");
    is($pubkey->getAddress(), $cases_compressed{$pubkey->toHex()}, "correctly created compressed address");
}

# Verify message without private key - 3 tests
my $message = "Perl test script";
my $pub = $PublicKey->fromHex("04b55965ca968e6e14d9175fb3fc3dc35f68b67b7e69cc2d1fa8c27f2406889c0f77cc2c39331735990bc67ccbf63c67642ff7b8ffd3794a4d76e0b78d9797a347");
my $pub_compressed = $PublicKey->fromHex("03b55965ca968e6e14d9175fb3fc3dc35f68b67b7e69cc2d1fa8c27f2406889c0f");
my $random_pub = $PublicKey->fromHex((keys %cases)[0]);
my $sig = pack_hex("3044022031731fbf940cffc6b72298b8775b12603fe16844a65983fb46b5fa8cf5d9e9bd022064625366f834314f8aef02aedc241a9b393d1f43887875f663b1be7080bae5c5");

ok($pub->verifyMessage($message, $sig), "verified message correctly");
ok($pub_compressed->verifyMessage($message, $sig), "verified message correctly with compressed key");
ok(!$random_pub->verifyMessage($message, $sig), "verification fails with different pubkey");

# Generate address for different network - 2 tests

$pub->setNetwork("testnet");
my $testnet_addr = "n1raSqPwHRbJ87dC8daiwgLVrQBy9Fj17K";
is($pub->network->{name}, "Bitcoin Testnet", "changed network to testnet");
is($pub->getAddress(), $testnet_addr, "created different address correctly when in non-default network");
