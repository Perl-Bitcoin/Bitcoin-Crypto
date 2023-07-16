use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);

my $tx;

subtest 'should verify transactions (P2PK)' => sub {
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

	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	lives_ok { $tx->verify } 'input verification ok';
};

subtest 'should verify transactions (P2PKH)' => sub {
	$tx = btc_transaction->new;

	btc_utxo->new(
		txid => [hex => '5fb32a2b34f497274419100cfa8f79c21029e8a415936366b2b058b992f55fdf'],
		output_index => 5,
		output => {
			locking_script => [P2PKH => '1C4mZbfHfLLEMJWd68WSaTZTPF2RFPYmWU'],
			value => 139615,
		},
	)->register;

	my $expected_txid = '1fe80a48f4746b214987fb8bef35046882b801a524df92dc1e3917b541bdd9d7';

	$tx->add_input(
		utxo => [[hex => '5fb32a2b34f497274419100cfa8f79c21029e8a415936366b2b058b992f55fdf'], 5],
		signature_script => btc_script->new
			->push(
				[
					hex =>
					'3044022057b2691a23ee0aa6727955029d2d3df0a763383e110780e54aa97cd89202a2c9022002dc9a8f03f433017dfc560311418c55565ca05f107fd21a679ecebe95cba1f401'
				]
			)
			->push([hex => '02a90be82f41c2a02706edb8efb8e3e4b7a94a0588cba991a0409bd9f08c79040a']),
	);

	$tx->add_output(
		value => 137615,
		locking_script => [P2PKH => '12s4mjQcz6rLpF8EyVGxFEFrgVKmNiPXxg'],
	);

	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	lives_ok { $tx->verify } 'input verification ok';
};

done_testing;

