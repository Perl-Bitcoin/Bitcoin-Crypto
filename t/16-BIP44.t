use v5.10;
use warnings;
use Test::More;

BEGIN { use_ok('Bitcoin::Crypto::BIP44') }

my $bip44 = Bitcoin::Crypto::BIP44->new(
	coin_type => 0,
	account => 1,
	change => 1,
	index => 2,
);

is "$bip44", "m/44'/0'/1'/1/2";

done_testing;
