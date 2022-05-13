use v5.10;
use strict;
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

subtest 'extended private key has bip44 helper' => sub {
	my $key = btc_extprv->from_mnemonic(
		'spawn impact body ask nothing warm farm novel host later basic subject point resist pilot'
	);
	$key->set_network('bitcoin_testnet');

	is $key->derive_key_bip44(account => 3, index => 4)->get_basic_key->to_wif,
		'cSTUMXWSBL5oiA6vVTN9jcN1kE59pbFuYPSeE8Q1L4mwpMw8ybo1';
	is $key->derive_key_bip44(coin_type => 25, account => 3, index => 4)->get_basic_key->to_wif,
		'cSTUMXWSBL5oiA6vVTN9jcN1kE59pbFuYPSeE8Q1L4mwpMw8ybo1';
};

subtest 'can derive bip49' => sub {
	my $key = btc_extprv->from_mnemonic(
		'spawn impact body ask nothing warm farm novel host later basic subject point resist pilot'
	);

	my $derived = $key->derive_key_bip44(purpose => 49, account => 3, index => 4)->get_basic_key;
	is $derived->to_wif, 'Kyji1MGDJXN88tG1DkZgqGgHEjhuSGYxVeXBaEFvEQrDReAkMDAZ';
	is $derived->get_public_key->get_compat_address, '3MzCdGHkbasTkxPMTMYQa3Tp7okMCceY7K';
};

subtest 'can derive bip84' => sub {
	my $key = btc_extprv->from_mnemonic(
		'spawn impact body ask nothing warm farm novel host later basic subject point resist pilot'
	);

	my $derived = $key->derive_key_bip44(purpose => 84, account => 3, index => 4)->get_basic_key;
	is $derived->to_wif, 'L5CXRMnEVSZ7j23VJ22mib3e4UWnb7utEpkDQtfTPn8DL9EEtTQZ';
	is $derived->get_public_key->get_segwit_address, 'bc1qs9370rhcdq8jtnxgq4cz93sthh9gtq3036dlw7';
};

subtest 'can derive account key' => sub {
	my $key = btc_extprv->from_mnemonic(
		'spawn impact body ask nothing warm farm novel host later basic subject point resist pilot'
	);

	my $derived = $key->derive_key_bip44(account => 3, get_account => 1);
	is $derived->to_serialized_base58,
		'xprv9yuRwketYqkKMDaaiJ9TmygWzquPJV8Bfw7cENzYtbgcnhg8ZFgjxDS9bQaXT5RcNfWf5QiwGD4573SvWnQpKvw8ZqCehftBSmHNkaM83cf';
};

done_testing;

