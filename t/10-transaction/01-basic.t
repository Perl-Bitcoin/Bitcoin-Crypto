use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_script btc_transaction);
use Bitcoin::Crypto::Transaction::UTXO;
use Bitcoin::Crypto::Util qw(to_format);

my $tx;

subtest 'should serialize transactions' => sub {
	$tx = btc_transaction->new;

	my $utxo = Bitcoin::Crypto::Transaction::UTXO->new(
		txid => [hex => 'a34b7271d2add50bb6eaeaaaffaebe33bf4e3fe0454ca5d46ab64e6dbbbf1174'],
		output_index => 0,
		output => {
			locking_script => [P2WPKH => 'bc1q7x7ua3s92k8gayvl8ltlqympxf53z075z486r2'],
			value => 198959,
		},
	)->register;

	my $expected_txid = '35a5c65c26549079d8369a2d445a79e0c195f4651495eb6f360a3e8766e30757';
	my $expected =
		'010000000001017411bfbb6d4eb66ad4a54c45e03f4ebf33beaeffaaeaeab60bd5add271724ba30000000000ffffffff026ef80200000000001976a914cf0d26e32df5b94905a7f372e4db12132be29f8e88ac140f00000000000016001428487e88a2870efdd700526a8904cfd78293a6780247304402201c57d633dea588b7c7e5b42e3fd72b7131c154293032dde60e380844403c2402022075a9eb1690de8b2dde0d45d643bcb64ad0c1782ca4cf1a9ca37c0b92e70501330121023a95ab5d95fd2ca4a849e66124e55a549a6e7573dfed0b7356f74ac3862f390100000000';

	$tx->add_input(
		utxo => $utxo,
		signature_script => '',
	);

	$tx->add_output(
		value => 194670,
		locking_script => [P2PKH => '1KsndX7cJH645NfWDqDYvkBWzJV6vKSDTB'],
	);

	$tx->add_output(
		value => 3860,
		locking_script => [P2WPKH => 'bc1q9py8az9zsu80m4cq2f4gjpx067pf8fnckxdxhd'],
	);

	$tx->add_witness(
		[
			hex =>
				'304402201c57d633dea588b7c7e5b42e3fd72b7131c154293032dde60e380844403c2402022075a9eb1690de8b2dde0d45d643bcb64ad0c1782ca4cf1a9ca37c0b92e705013301'
		],
		[hex => '023a95ab5d95fd2ca4a849e66124e55a549a6e7573dfed0b7356f74ac3862f3901']
	);

	is to_format [hex => $tx->to_serialized_witness], $expected, 'serialized ok';
	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	is $tx->fee, 429, 'fee ok';
	is substr($tx->fee_rate, 0, 4), '2.99', 'fee rate ok';
	is substr($tx->virtual_size, 0, 6), '143.25', 'vB weight ok';
	is $tx->weight, '573', 'WU weight ok';
};

subtest 'should digest transactions (old OP_CHECKSIG style)' => sub {
	$tx = btc_transaction->new;

	Bitcoin::Crypto::Transaction::UTXO->new(
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

subtest 'should update UTXOs' => sub {

	# NOTE: using the transaction from the last subtest
	$tx->update_utxos;

	throws_ok {
		Bitcoin::Crypto::Transaction::UTXO->get(
			[hex => '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'], 0
		);
	} 'Bitcoin::Crypto::Exception::UTXO';

	lives_ok {
		Bitcoin::Crypto::Transaction::UTXO->get(
			[hex => 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'], 0
		);
		Bitcoin::Crypto::Transaction::UTXO->get(
			[hex => 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'], 1
		);
	};

	throws_ok {
		Bitcoin::Crypto::Transaction::UTXO->get(
			[hex => 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'], 2
		);
	} 'Bitcoin::Crypto::Exception::UTXO';
};

done_testing;

