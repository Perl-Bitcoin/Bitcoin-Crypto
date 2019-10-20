use strict;
use warnings;

use Test::More;
use Try::Tiny;
use Bitcoin::Crypto::Helpers qw(pad_hex);
use Bitcoin::Crypto::Config;

$config{compress_public_point} = 0;

BEGIN { use_ok('Bitcoin::Crypto::Key::Public') };

my $PublicKey = "Bitcoin::Crypto::Key::Public";

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

my %cases_segwit_compat = qw(
	0332984aea6809830debe9f31dcb874b8b98a50b579d418184bf8ae55395c19567
	38bKkt524L2KTr76kNapMxnnPF3RUt9skS
	025ac07e3c241a7062f6144815320b86c9557bd4de71f05a37c2c3c8012994ef80
	34zCHfPoT8tdDuWBYEt7MxQKayDdmjnP1v
	03d939f548ad09b3f9130b7567d7b27d6862651f3363bc68b15676da56f26c994d
	35aWDrYGwEokTb22bYw2HbtXxySuAemo92
	0396aa08d4e14e4fd994f6618a4db40eb1f22b9368c6f4d48b77c43e1d852d6665
	3MPiebrSnMLCEPr8NsEemwHY1oUrKCCRcL
);

my %cases_segwit_native = qw(
	02041cd51a1d0df8fba2dd5a87b1b08bc83cfbd4b2c605334629ed99d14a26c051
	bc1q8u2wsar26p6z2r9ckh3t8xauhcm8sgzd2jzgkr
	0367fc07d2a9d6b95305ea1bc33a3b693a5d0f9a6a90c2bac86c67e79808fcc98d
	bc1qfrxtzat3nutef828dr5ua7seq5d6selpued3dy
	0332984aea6809830debe9f31dcb874b8b98a50b579d418184bf8ae55395c19567
	bc1qmhf3n5a06szyvp8yrr6ggcrpm3f7uyxsz62u29
	03765fd0392d349415328fa40b83b05088d188b54b7b5d7a6a20124b70c17bc129
	bc1q5v4slm3x0pteg7n7ldefgsn9jpdkkg6e985vek
);

# Basic creation of addresses keys - 8 tests
for my $key (keys %cases) {
	my $pubkey = $PublicKey->fromHex($key)->setCompressed(0);
	is($pubkey->toHex(), $key, "imported and exported correctly");
	is($pubkey->getLegacyAddress(), $cases{$key}, "correctly created address");
	$pubkey->setCompressed(1);
	ok(defined $cases_compressed{$pubkey->toHex()}, "exported compressed key correctly");
	is($pubkey->getLegacyAddress(), $cases_compressed{$pubkey->toHex()}, "correctly created compressed address");
}

# SegWit readiness
for my $key (keys %cases_segwit_compat) {
	my $pubkey = $PublicKey->fromHex($key);
	is($pubkey->getCompatAddress(), $cases_segwit_compat{$key}, "correctly created segwit compat address");
}

for my $key (keys %cases_segwit_native) {
	my $pubkey = $PublicKey->fromHex($key);
	is($pubkey->getSegwitAddress(), $cases_segwit_native{$key}, "correctly created segwit native address");
}

# Verify message without private key - 3 tests
my $message = "Perl test script";
my $pub = $PublicKey->fromHex("04b55965ca968e6e14d9175fb3fc3dc35f68b67b7e69cc2d1fa8c27f2406889c0f77cc2c39331735990bc67ccbf63c67642ff7b8ffd3794a4d76e0b78d9797a347")->setCompressed(0);
my $pub_compressed = $PublicKey->fromHex("03b55965ca968e6e14d9175fb3fc3dc35f68b67b7e69cc2d1fa8c27f2406889c0f");
my $random_pub = $PublicKey->fromHex((keys %cases)[0]);
my $sig = pack "H*", pad_hex("3044022031731fbf940cffc6b72298b8775b12603fe16844a65983fb46b5fa8cf5d9e9bd022064625366f834314f8aef02aedc241a9b393d1f43887875f663b1be7080bae5c5");

ok($pub->verifyMessage($message, $sig), "verified message correctly");
ok($pub_compressed->verifyMessage($message, $sig), "verified message correctly with compressed key");
ok(!$random_pub->verifyMessage($message, $sig), "verification fails with different pubkey");

# Generate address for different network - 2 tests

$pub->setNetwork("testnet");
my $testnet_addr = "n1raSqPwHRbJ87dC8daiwgLVrQBy9Fj17K";
is($pub->network->{name}, "Bitcoin Testnet", "changed network to testnet");
is($pub->getLegacyAddress(), $testnet_addr, "created different address correctly when in non-default network");

done_testing;
