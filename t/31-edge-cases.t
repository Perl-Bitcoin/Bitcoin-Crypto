use Test2::V0;
use Bitcoin::Crypto qw(:all);
use Bitcoin::Crypto::Base58 qw(:all);
use Bitcoin::Crypto::Bech32 qw(:all);
use Bitcoin::Crypto::Util qw(generate_mnemonic);
use Bitcoin::Crypto::Network;

subtest 'testing invalid hex' => sub {
	isa_ok dies {
		btc_pub->from_serialized([hex => 'not-a-hex']);
	}, 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'testing undef as a bytestring' => sub {
	like dies {
		btc_pub->from_serialized(undef);
	}, qr/not a bytestring/;
};

subtest 'testing empty string as a bytestring' => sub {
	isa_ok dies {
		btc_pub->from_serialized('');
	}, 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'testing reference as a bytestring' => sub {
	like dies {
		btc_pub->from_serialized(['11']);
	}, qr/not a bytestring/;
};

subtest 'testing invalid base58' => sub {
	isa_ok dies {
		decode_base58('158ZaF+');
	}, 'Bitcoin::Crypto::Exception::Base58InputFormat';
};

subtest 'testing invalid bech32' => sub {
	isa_ok dies {
		decode_bech32('bc1+-aaa');
	}, 'Bitcoin::Crypto::Exception::Bech32InputFormat';
};

subtest 'should not handle importing unknown wif' => sub {
	my $wif = 'VHC6BRSLeqgpZYSgLDFfA5tG1LKSk1j9DZczQKNQA3kJVctM4D8h';
	isa_ok dies {
		my $key = btc_prv->from_wif($wif);
	}, 'Bitcoin::Crypto::Exception::NetworkConfig';
};

subtest 'should not handle importing unknown wif with network parameter' => sub {
	my $wif = 'VHC6BRSLeqgpZYSgLDFfA5tG1LKSk1j9DZczQKNQA3kJVctM4D8h';
	isa_ok dies {
		my $key = btc_prv->from_wif($wif, 'bitcoin');
	}, 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'should not handle importing unknown serialized prv' => sub {
	my $ser =
		'Ltpv71G8qDifUiNetg7qxKgZqxMZM1Dy8zeEb7Bz14gE1ZJdVY5xnHEyREwWRYpKTJHD3rS9T3YDvyRNcWaeBp64XWSsDWNST2co9S4eU1Cxz7c';
	isa_ok dies {
		my $key = btc_extprv->from_serialized([base58 => $ser]);
	}, 'Bitcoin::Crypto::Exception::NetworkConfig';
};

subtest 'should not handle importing unknown serialized prv with network parameter' => sub {
	my $ser =
		'Ltpv71G8qDifUiNetg7qxKgZqxMZM1Dy8zeEb7Bz14gE1ZJdVY5xnHEyREwWRYpKTJHD3rS9T3YDvyRNcWaeBp64XWSsDWNST2co9S4eU1Cxz7c';
	isa_ok dies {
		my $key = btc_extprv->from_serialized([base58 => $ser], 'bitcoin');
	}, 'Bitcoin::Crypto::Exception::KeyCreate';
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

subtest 'should handle importing wif (multiple networks) with default' => sub {
	my $wif = '5JxsKGzCoJwaWEjQvfNqD4qPEoUQ696BUEq68Y68WQ2GNR6zrxW';
	my $key = btc_prv->from_wif($wif);
	is $key->network->id, 'bitcoin';
};

subtest 'should not handle importing wif (multiple networks) if default is not one of the networks' => sub {
	my $old_default = Bitcoin::Crypto::Network->get;
	Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

	my $wif = '5JxsKGzCoJwaWEjQvfNqD4qPEoUQ696BUEq68Y68WQ2GNR6zrxW';
	like dies {
		my $key2 = btc_prv->from_wif($wif);
	}, qr{multiple networks};

	$old_default->set_default;
};

subtest 'should handle importing serialized prv (multiple networks) with network parameter' => sub {
	my $ser =
		'xprv9xoYZivLq3T7RYS1sN5uhzQDyGk7gkfvgUKgD7gzwtUGbPu8LxMexvZE39x4Te5r62ekj9aNrjxcfDm4Di3qmHLKeacnmkfQWY8Xubba1Ya';
	my $key = btc_extprv->from_serialized([base58 => $ser], 'bitcoin2');
	is $key->network->id, 'bitcoin2';
};

subtest 'should handle importing serialized prv (multiple networks) with default' => sub {
	my $ser =
		'xprv9xoYZivLq3T7RYS1sN5uhzQDyGk7gkfvgUKgD7gzwtUGbPu8LxMexvZE39x4Te5r62ekj9aNrjxcfDm4Di3qmHLKeacnmkfQWY8Xubba1Ya';
	my $key = btc_extprv->from_serialized([base58 => $ser]);
	is $key->network->id, 'bitcoin';
};

subtest 'should not handle importing wif (multiple networks) if default is not one of the networks' => sub {
	my $old_default = Bitcoin::Crypto::Network->get;
	Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

	my $ser =
		'xprv9xoYZivLq3T7RYS1sN5uhzQDyGk7gkfvgUKgD7gzwtUGbPu8LxMexvZE39x4Te5r62ekj9aNrjxcfDm4Di3qmHLKeacnmkfQWY8Xubba1Ya';
	like dies {
		my $key = btc_extprv->from_serialized([base58 => $ser]);
	}, qr{multiple networks};

	$old_default->set_default;
};

subtest 'refuses to create keys with invalid network in single-network mode' => sub {
	Bitcoin::Crypto::Network->get->set_single;

	my $ser =
		'tpubDC9sLxZVcV2s4Kwy2RjcYnjwks6zuWvekLpfwtAPvrntwSDUQAyt27DdDRHwDL63NxX7RuXD7Bgw7Qaf4vvssYdcVuv5MfvkFjZiDiRsfC7';
	like dies {
		my $pub = btc_extpub->from_serialized([base58 => $ser], 'bitcoin_testnet');
	}, qr{single-network mode with bitcoin};

	Bitcoin::Crypto::Network->get->set_default;
};

subtest 'refuses to change network in single-network mode' => sub {
	Bitcoin::Crypto::Network->get->set_single;

	my $ser =
		'xprv9xoYZivLq3T7RYS1sN5uhzQDyGk7gkfvgUKgD7gzwtUGbPu8LxMexvZE39x4Te5r62ekj9aNrjxcfDm4Di3qmHLKeacnmkfQWY8Xubba1Ya';
	my $key = btc_extprv->from_serialized([base58 => $ser]);

	like dies {
		$key->set_network('bitcoin2');
	}, qr{single-network mode with bitcoin};

	Bitcoin::Crypto::Network->get->set_default;
};

done_testing;

