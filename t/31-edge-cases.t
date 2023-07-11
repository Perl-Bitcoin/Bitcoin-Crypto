use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(:all);
use Bitcoin::Crypto::Base58 qw(:all);
use Bitcoin::Crypto::Bech32 qw(:all);
use Bitcoin::Crypto::Util qw(generate_mnemonic);
use Bitcoin::Crypto::Network;

subtest 'testing invalid hex' => sub {
	throws_ok {
		btc_pub->from_serialized([hex => 'not-a-hex']);
	} 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'testing undef as a bytestring' => sub {
	throws_ok {
		btc_pub->from_serialized(undef);
	} qr/not a bytestring/;
};

subtest 'testing empty string as a bytestring' => sub {
	throws_ok {
		btc_pub->from_serialized('');
	} 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'testing reference as a bytestring' => sub {
	throws_ok {
		btc_pub->from_serialized(['11']);
	} qr/not a bytestring/;
};

subtest 'testing invalid verification algorithm' => sub {
	my $master_key = btc_extprv->from_mnemonic(generate_mnemonic);
	my $private_key = $master_key->get_basic_key;
	my $public_key = $private_key->get_public_key;

	throws_ok {
		$public_key->verify_message('message', "\x00", 'not-a-hashing-algo');
	} 'Bitcoin::Crypto::Exception::Verify';
};

subtest 'testing invalid base58' => sub {
	throws_ok {
		decode_base58('158ZaF+');
	} 'Bitcoin::Crypto::Exception::Base58InputFormat';
};

subtest 'testing invalid bech32' => sub {
	throws_ok {
		decode_bech32('bc1+-aaa');
	} 'Bitcoin::Crypto::Exception::Bech32InputFormat';
};

subtest 'should not handle importing unknown wif' => sub {
	my $wif = 'VHC6BRSLeqgpZYSgLDFfA5tG1LKSk1j9DZczQKNQA3kJVctM4D8h';
	throws_ok {
		my $key = btc_prv->from_wif($wif);
	} 'Bitcoin::Crypto::Exception::NetworkConfig';
};

subtest 'should not handle importing unknown wif with network parameter' => sub {
	my $wif = 'VHC6BRSLeqgpZYSgLDFfA5tG1LKSk1j9DZczQKNQA3kJVctM4D8h';
	throws_ok {
		my $key = btc_prv->from_wif($wif, 'bitcoin');
	} 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'should not handle importing unknown serialized prv' => sub {
	my $ser =
		'Ltpv71G8qDifUiNetg7qxKgZqxMZM1Dy8zeEb7Bz14gE1ZJdVY5xnHEyREwWRYpKTJHD3rS9T3YDvyRNcWaeBp64XWSsDWNST2co9S4eU1Cxz7c';
	throws_ok {
		my $key = btc_extprv->from_serialized([base58 => $ser]);
	} 'Bitcoin::Crypto::Exception::NetworkConfig';
};

subtest 'should not handle importing unknown serialized prv with network parameter' => sub {
	my $ser =
		'Ltpv71G8qDifUiNetg7qxKgZqxMZM1Dy8zeEb7Bz14gE1ZJdVY5xnHEyREwWRYpKTJHD3rS9T3YDvyRNcWaeBp64XWSsDWNST2co9S4eU1Cxz7c';
	throws_ok {
		my $key = btc_extprv->from_serialized([base58 => $ser], 'bitcoin');
	} 'Bitcoin::Crypto::Exception::KeyCreate';
};

Bitcoin::Crypto::Network->register(
	id => 'bitcoin2',
	name => 'Bitcoin Mainnet Clone',
	p2pkh_byte => "\x00",
	p2sh_byte => "\x05",
	wif_byte => "\x80",
	segwit_hrp => 'bc',

	extprv_version => 0x0488ade4,
	extpub_version => 0x0488b21e,

	extprv_compat_version => 0x049d7878,
	extpub_compat_version => 0x049d7cb2,

	extprv_segwit_version => 0x04b2430c,
	extpub_segwit_version => 0x04b24746,

	bip44_coin => 0,
);

subtest 'should handle importing wif (multiple networks) with network parameter' => sub {
	my $wif = '5JxsKGzCoJwaWEjQvfNqD4qPEoUQ696BUEq68Y68WQ2GNR6zrxW';
	my $key = btc_prv->from_wif($wif, 'bitcoin2');
	is $key->network->id, 'bitcoin2';
};

subtest 'should handle importing serialized prv (multiple networks) with network parameter' => sub {
	my $ser =
		'xprv9xoYZivLq3T7RYS1sN5uhzQDyGk7gkfvgUKgD7gzwtUGbPu8LxMexvZE39x4Te5r62ekj9aNrjxcfDm4Di3qmHLKeacnmkfQWY8Xubba1Ya';
	my $key = btc_extprv->from_serialized([base58 => $ser], 'bitcoin2');
	is $key->network->id, 'bitcoin2';
};

done_testing;

