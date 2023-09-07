use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);

btc_utxo->extract(
	[
		hex =>
			'01000000000102282ec65923be2ee5e1ea180d209dc32c7b34d6955d122cae6e189062c631f45d0100000000fbffffffd9bd0e72812c5cb04e4e0b2a151f67e70c8b21dce47c95c86c957be9c4dc42f91100000000faffffff022f09030000000000160014f1bdcec605558e8e919f3fd7f013613269113fd4e207000000000000160014371348efc5133fb3244a7568e2566b74e71be5ac02483045022100bfe10eeae67d6022eb22d75b10f9d26e75c6325918e2b1f23e37435db1a16bc602207c987432a63704b84e655c8f66740b7d7b1d8f8ecf286251c4d5f7dc13aeeb1d012102f5594a930e3d125f5f5b826ddf369d2813a61bc5c1c34167b323376ae046e25902483045022100b43ebcfacd59b65c8856b0ae05ca2a12e6d759c574e24fc33fadfadf36d1f3da022003856fd0a30d79239f3dbf1129a9d9cb4e24333bd1f0a61735649f688aeabf19012102f5594a930e3d125f5f5b826ddf369d2813a61bc5c1c34167b323376ae046e25900000000'
	]
);

my $tx = btc_transaction->new;
my $expected_txid = '35a5c65c26549079d8369a2d445a79e0c195f4651495eb6f360a3e8766e30757';
my $expected_serialized =
	'010000000001017411bfbb6d4eb66ad4a54c45e03f4ebf33beaeffaaeaeab60bd5add271724ba30000000000ffffffff026ef80200000000001976a914cf0d26e32df5b94905a7f372e4db12132be29f8e88ac140f00000000000016001428487e88a2870efdd700526a8904cfd78293a6780247304402201c57d633dea588b7c7e5b42e3fd72b7131c154293032dde60e380844403c2402022075a9eb1690de8b2dde0d45d643bcb64ad0c1782ca4cf1a9ca37c0b92e70501330121023a95ab5d95fd2ca4a849e66124e55a549a6e7573dfed0b7356f74ac3862f390100000000';

$tx->add_input(
	utxo => [[hex => 'a34b7271d2add50bb6eaeaaaffaebe33bf4e3fe0454ca5d46ab64e6dbbbf1174'], 0],
	witness => [
		[
			hex =>
				'304402201c57d633dea588b7c7e5b42e3fd72b7131c154293032dde60e380844403c2402022075a9eb1690de8b2dde0d45d643bcb64ad0c1782ca4cf1a9ca37c0b92e705013301'
		],
		[hex => '023a95ab5d95fd2ca4a849e66124e55a549a6e7573dfed0b7356f74ac3862f3901']
	],
);

$tx->add_output(
	value => 194670,
	locking_script => [P2PKH => '1KsndX7cJH645NfWDqDYvkBWzJV6vKSDTB'],
);

$tx->add_output(
	value => 3860,
	locking_script => [P2WPKH => 'bc1q9py8az9zsu80m4cq2f4gjpx067pf8fnckxdxhd'],
);

subtest 'basic transaction data ok' => sub {
	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	is $tx->fee, 429, 'fee ok';
	is substr($tx->fee_rate, 0, 4), '2.99', 'fee rate ok';
	is substr($tx->virtual_size, 0, 6), '143.25', 'vB weight ok';
	is $tx->weight, '573', 'WU weight ok';
};

subtest 'should serialize transactions' => sub {
	is to_format [hex => $tx->to_serialized], $expected_serialized, 'serialization ok';
};

subtest 'should deserialize transactions' => sub {
	my $deserialized = btc_transaction->from_serialized([hex => $expected_serialized]);
	is to_format [hex => $deserialized->to_serialized], $expected_serialized, 'deserialization ok';
};

subtest 'should update UTXOs' => sub {
	$tx->update_utxos;

	throws_ok {
		btc_utxo->get(
			[hex => 'a34b7271d2add50bb6eaeaaaffaebe33bf4e3fe0454ca5d46ab64e6dbbbf1174'], 0
		);
	} 'Bitcoin::Crypto::Exception::UTXO';

	lives_ok {
		btc_utxo->get(
			[hex => '35a5c65c26549079d8369a2d445a79e0c195f4651495eb6f360a3e8766e30757'], 0
		);
		btc_utxo->get(
			[hex => '35a5c65c26549079d8369a2d445a79e0c195f4651495eb6f360a3e8766e30757'], 1
		);
	};

	throws_ok {
		btc_utxo->get(
			[hex => '35a5c65c26549079d8369a2d445a79e0c195f4651495eb6f360a3e8766e30757'], 2
		);
	} 'Bitcoin::Crypto::Exception::UTXO';
};

done_testing;

