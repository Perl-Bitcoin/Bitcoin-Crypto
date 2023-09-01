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

subtest 'should verify transactions (P2SH)' => sub {
	$tx = btc_transaction->new;

	btc_utxo->new(
		txid => [hex => '81d5859d7db9b3d2da0fd4e8abd4b3005febb8fa72f0e4bd3687fd1863b1bd36'],
		output_index => 50,
		output => {
			locking_script => [P2SH => '3HSZTsuakivAbX9cA7A6ayt6cf546WU6Bm'],
			value => 4_89995000,
		},
	)->register;

	my $expected_txid = '92f100a9ea54b9daddaff5f7c409f82c6037053bc5deb35d7c49bc07dd4121e7';

	$tx->add_input(
		utxo => [[hex => '81d5859d7db9b3d2da0fd4e8abd4b3005febb8fa72f0e4bd3687fd1863b1bd36'], 50],
		signature_script => btc_script->new
			->add('OP_0')
			->push(
				[
					hex =>
					'30440220654390a02b4ed6a7e1677cb5b363b831ad47fec2b409986b2e281e9c9f308e970220738582d89867fb19207a1f14a0b6e1bbcfd6ee2dbcebb3e0d55f6ff67c7ccff601'
				]
			)
			->push(
				[
					hex =>
					'3044022050bbd062653aaaf9f0292e4a97cafa831999be6876b0df43de646df4804f6ac8022003d4404d3e1d72ae20058d1b5d455f19caceb9f6b1a21a8729a678b42a90666701'
				]
			)
			->push(
				[
					hex =>
					'52210304d71378c1ad693c876a92a57aad057b1f5a17517f9b7ca2f736b7e0cd968f352103c79161e4888885e664cc2708638a5e39a506f6f483e3f4fe45148dfd5618adbf4104c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f880326dbd66c140b50257f9618173833b50b6e829b5cd04ffd0ba693b90be80435953ae'
				]
			)
	);

	$tx->add_output(
		value => 1_66313000,
		locking_script => [P2WSH => 'bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej'],
	);

	$tx->add_output(
		value => 3_23623560,
		locking_script => [P2WSH => 'bc1qyy30guv6m5ez7ntj0ayr08u23w3k5s8vg3elmxdzlh8a3xskupyqn2lp5w'],
	);

	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	lives_ok { $tx->verify } 'input verification ok';
};

subtest 'should verify transactions (P2WPKH)' => sub {

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
				'01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000'
		]
	);

	lives_ok { $tx->verify } 'input verification ok';

	# NOTE: try modifying witness signature, see if it still verifies
	# (segwit transactions are backward compatible, so it would pass without support for segwit)
	$tx->inputs->[0]->witness->[1][0] = "\x00\x01";
	dies_ok { $tx->verify } 'input verification ok after modifying witness';
};

done_testing;

