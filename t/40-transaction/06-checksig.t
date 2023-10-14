use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use lib 't/lib';

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo btc_block);
use Bitcoin::Crypto::Util qw(to_format);
use TransactionStore;

my $tx;

subtest 'should verify transactions (P2PK)' => sub {
	$tx = btc_transaction->new;

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
		value => '40_00000000',
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

subtest 'should verify transactions (P2PKH, two inputs)' => sub {
	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'01000000026441f74993e2f89570c45770b1db083dc65cc5dc61f730cb8f447b0ce766dbee000000006a473044022021d09363ef5282bef504b8f5e8616e29469605e663cf3611bfbfb9b52dc8fee202206841ac5f6d21c7e6dea28f7cfafb4cf45c0f6e84883d3df3f4309e9e5339d46d0121029da9229a24fb021f644dd2a1f11841d339a292609acb71552e8578d409e63c97ffffffff62d5b94e8aa3de7dccf36711d226644a1fce6c4fb3f891b97054961ebc6e7f66010000006b483045022100e4b5e5e0a352db2738fc024327cff6a0460db87cc0c0dfa9ddc6a558977eff1802205f867d2ea2b594cf9e87152bd6e9383836b1e1514e18faa801e4d87112fb37cd01210365c679364587685a479b1f6da15f34111626e04235e831eb2259ba817ff7c1cbffffffff0280f0fa02000000001976a9144b5474ef9b686ca5858b2ddccf669b6fd397b3bb88ac006a1800000000001976a9143b9051cd8c015af58322dd89f69872f2f57bd24f88ac00000000'
		]
	);

	my $expected_txid = '03b26c89e180fd51ee12cb232559214bbb80d9db230ab65761b4d59018d076cc';

	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	lives_ok { $tx->verify } 'input verification ok';
};

subtest 'should verify transactions (P2SH)' => sub {
	$tx = btc_transaction->new;

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

	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000'
		]
	);

	# not a real transaction, so it does not belong to this block
	my $block = btc_block->new(
		timestamp => 1694665785,
		height => 807567,
	);

	lives_ok { $tx->verify(block => $block) } 'input verification ok';
	lives_ok { $tx->verify(block => $block) } 'input verification ok (second time)';

	# NOTE: try modifying witness signature, see if it still verifies
	# (segwit transactions are backward compatible, so it would pass without support for segwit)
	$tx->inputs->[1]->witness->[0] .= "\x01";
	throws_ok { $tx->verify(block => $block) } 'Bitcoin::Crypto::Exception::Transaction',
		'input verification ok after modifying witness';
};

subtest 'should verify transactions (nested P2WPKH)' => sub {
	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'02000000000102e989f39b4b172387fb290d459e3d957e4d3721ff808b3a82ca81d09577ec9a640300000017160014a6997673a7f0cbf989da7595da2b3518e9197ee4fdffffffa974b7f14d0c510c7dddbaf670c43ff050e11a6d3634465f6406cb8473307ae01700000017160014007f740fbf029c3a1eec99f2a885ebce5be3ddfbfdffffff016ceb1400000000001600149d5c6e207e729a18e2e100a94f98ae1b8cb9530702473044022020b626dc4801f541d5aa88d3c04e41a296a620c6136b8b38475ac19f05fad13f02204ea80951f21d30f5275500ad68d9cd7fb6b1f2a01bba2ff059e1c33959041263012103b56150c6fc69818b2f32614b3c178419af81cc3dbd8b55483d0cbfc7149094930247304402204cb28cc4b9898c64c2929b16bba9f62c1e2c880222e8ebca810dce9ae8d634f502201a1fd513e8a9a2a64162b04cf81015f138d4563c5338aab923e35345df3318cd0121027cabde34fa38a89523129bf310af8975f39d8493e863fd1f945711b85b5753618e520c00'
		]
	);

	my $block = btc_block->new(
		timestamp => 1694665785,
		height => 807567,
	);

	lives_ok { $tx->verify(block => $block) } 'input verification ok';
	lives_ok { $tx->verify(block => $block) } 'input verification ok (second time)';

	# NOTE: try modifying witness signature, see if it still verifies
	# (segwit transactions are backward compatible, so it would pass without support for segwit)
	$tx->inputs->[0]->witness->[1] .= "\x01";
	throws_ok { $tx->verify(block => $block) } 'Bitcoin::Crypto::Exception::Transaction',
		'input verification ok after modifying witness';
};

done_testing;

