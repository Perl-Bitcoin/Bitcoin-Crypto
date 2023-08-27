use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);

my $tx;
subtest 'should digest transactions - legacy SIGHASH_ALL' => sub {
	$tx = btc_transaction->new;

	btc_utxo->new(
		txid => [hex => '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'],
		output_index => 0,
		output => {
			locking_script => [
				P2PK => [
					hex =>
						'0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3'
				]
			],
			value => 50_00000000,
		},
	)->register;

	my $expected_txid = 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16';
	my $expected =
		'0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37040000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3acffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac0000000001000000';

	$tx->add_input(
		utxo => [[hex => '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'], 0],
		signature_script => btc_script->new
			->push(
				[
					hex =>
					'304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901'
				]
			),
	);

	$tx->add_output(
		value => 10_00000000,
		locking_script => [
			P2PK => [
				hex =>
					'04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c'
			]
		],
	);

	$tx->add_output(
		value => 40_00000000,
		locking_script => [
			P2PK => [
				hex =>
					'0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3'
			]
		],
	);

	is to_format [hex => $tx->get_hash], $expected_txid, 'hash ok';
	is to_format [hex => $tx->get_digest(signing_index => 0)], $expected, 'digest ok';
};

subtest 'should digest transactions - native segwit SIGHASH_ALL' => sub {

	# from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh

	btc_utxo->new(
		txid => [hex => '9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff'],
		output_index => 0,
		output => {
			locking_script => [hex => '2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac'],
			value => 6_25000000,
		},
	)->register;

	btc_utxo->new(
		txid => [hex => '8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef'],
		output_index => 1,
		output => {
			locking_script => [hex => '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'],
			value => 6_00000000,
		},
	)->register;

	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000'
		]
	);

	my $expected =
		'0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000';

	is to_format [hex => $tx->get_digest(signing_index => 1)], $expected, 'digest ok';
};

done_testing;

