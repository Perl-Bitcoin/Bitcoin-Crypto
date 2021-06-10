use v5.10;
use warnings;
use Test::More;
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto qw(btc_extprv);
use Bitcoin::Crypto::Util qw(get_path_info);

BEGIN { use_ok('Bitcoin::Crypto::BIP44') }

subtest 'coin_type is an integer' => sub {
	my $bip44 = Bitcoin::Crypto::BIP44->new(
		coin_type => 0,
		account => 1,
		change => 1,
		index => 2,
	);

	is "$bip44", "m/44'/0'/1'/1/2";
};

subtest 'coin_type is a network' => sub {
	my $bip44 = Bitcoin::Crypto::BIP44->new(
		coin_type => Bitcoin::Crypto::Network->get('bitcoin_testnet'),
		account => 1,
		change => 1,
		index => 2,
	);

	is "$bip44", "m/44'/1'/1'/1/2";
};

subtest 'coin_type does network role' => sub {
	my $mnemonic = btc_extprv->generate_mnemonic;
	my $key = btc_extprv->from_mnemonic($mnemonic);
	$key->set_network('bitcoin_testnet');

	my $bip44 = Bitcoin::Crypto::BIP44->new(
		coin_type => $key,
		account => 0,
		change => 0,
		index => 5,
	);

	is "$bip44", "m/44'/1'/0'/0/5";
};

subtest 'get_path_info understands bip44' => sub {
	my $bip44 = Bitcoin::Crypto::BIP44->new(
		coin_type => 300,
		account => 200,
		change => 1,
		index => 100000,
	);

	is_deeply get_path_info($bip44), {
		private => !!1,
		path => [
			44 + (2 << 30),
			300 + (2 << 30),
			200 + (2 << 30),
			1,
			100000,
		],
	};
};

subtest 'bip44 can be used directly in key derivation' => sub {
	my $key = btc_extprv->from_mnemonic(
		'spawn impact body ask nothing warm farm novel host later basic subject point resist pilot'
	);

	my $bip44 = Bitcoin::Crypto::BIP44->new(
		account => 5,
		index => 6,
	);

	is $key->derive_key($bip44)->get_basic_key->to_wif, 'L4cAPkgogiSuiySepNFsrWoB2wdCVGCkuNT4se1U6A59xTaJbeFz';
};

done_testing;
