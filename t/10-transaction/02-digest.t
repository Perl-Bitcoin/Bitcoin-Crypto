use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use lib 't/lib';

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Constants;
use TransactionStore;

my $tx;

subtest 'should digest transactions - legacy' => sub {
	subtest 'should digest SIGHASH_ALL' => sub {
		$tx = btc_transaction->new;

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

	# Other sighashes - all from single transaction
	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'0100000003ae8fe99eac2ced7681fdd2aedd25a83ff88fbed347571a2d7cb54aeb85a883f4010000006a473044022012048b6ac38277642e24e012267cf91c22326c3b447d6b4056698f7c298fb36202201139039bb4090a7cfb63c57ecc60d0ec8b7483bf0461a468743022759dc50124012102317ee6cd0c43381825bfe8bb0a51d46195dc36eca6adc7bb4bd2ead6a0909be0ffffffff5704be9a882060ac36f96e204553e92d37c78f831d84dce32832f4c0b919e594000000006a47304402207601fb44eab2eaf87b7988e672657c763d7ba0337cf19a3ba8fcdee55da483ec022067122f2e4aa523b1a081ad2b7a94a90cca16cd2a5214b31649a2e8aaf5565427012102dec5f30310c48e3ced04237a995469c41182383ee403d904ccb19ef85feaafa9ffffffff5704be9a882060ac36f96e204553e92d37c78f831d84dce32832f4c0b919e594010000006a473044022002f924830a1cf8214da7601e17a74d5e197c3f9b043d2964b4b4e99cfaf38f8402201587208194bc578e17d274ce5d7db253ce48d24ddd4f574377535d437351a74f0121032a934955fbdd4601265c801150f999ba6cda536de2dbfcab7d6912c803211b9bffffffff0563fb7805000000001976a914cd2be655e57086668a5be28c02f5563c06a1b47b88aca3738402000000001976a914ddcb7fedaacc18da645a2d7ffdabbc24880e288a88aca71b9a00000000001976a91486165b6dc00d1ae52685ed594f8262f39ec0150c88ac867f0d03000000001976a91421b95ee973b8966ff6cf039969491801cc42f1a088ace7489601000000001976a914c879015ab911026b277e48231a2bf256c6e9492688ac00000000'
		]
	);

	subtest 'should digest SIGHASH_NONE' => sub {
		my $expected =
			'0100000003ae8fe99eac2ced7681fdd2aedd25a83ff88fbed347571a2d7cb54aeb85a883f4010000001976a91415c055fa681fef5f8d342fc63b730648120679b388acffffffff5704be9a882060ac36f96e204553e92d37c78f831d84dce32832f4c0b919e594000000000100000000005704be9a882060ac36f96e204553e92d37c78f831d84dce32832f4c0b919e59401000000010000000000000000000002000000';

		is to_format [
			hex => $tx->get_digest(signing_index => 0, sighash => Bitcoin::Crypto::Constants::sighash_none)
			],
			$expected, 'digest ok';
	};

	subtest 'should digest SIGHASH_SINGLE' => sub {
		my $expected =
			'0100000003ae8fe99eac2ced7681fdd2aedd25a83ff88fbed347571a2d7cb54aeb85a883f4010000000100000000005704be9a882060ac36f96e204553e92d37c78f831d84dce32832f4c0b919e594000000001976a9147df526887e47d6af7e89b35f8304dd2cf7519b3c88acffffffff5704be9a882060ac36f96e204553e92d37c78f831d84dce32832f4c0b919e5940100000001000000000002ffffffffffffffff0100a3738402000000001976a914ddcb7fedaacc18da645a2d7ffdabbc24880e288a88ac0000000003000000';

		is to_format [
			hex => $tx->get_digest(signing_index => 1, sighash => Bitcoin::Crypto::Constants::sighash_single)
			],
			$expected, 'digest ok';
	};

	subtest 'should digest SIGHASH_ALL | SIGHASH_ANYONECANPAY' => sub {
		my $expected =
			'01000000015704be9a882060ac36f96e204553e92d37c78f831d84dce32832f4c0b919e594000000001976a9147df526887e47d6af7e89b35f8304dd2cf7519b3c88acffffffff0563fb7805000000001976a914cd2be655e57086668a5be28c02f5563c06a1b47b88aca3738402000000001976a914ddcb7fedaacc18da645a2d7ffdabbc24880e288a88aca71b9a00000000001976a91486165b6dc00d1ae52685ed594f8262f39ec0150c88ac867f0d03000000001976a91421b95ee973b8966ff6cf039969491801cc42f1a088ace7489601000000001976a914c879015ab911026b277e48231a2bf256c6e9492688ac0000000081000000';

		is to_format [
			hex => $tx->get_digest(
				signing_index => 1,
				sighash => Bitcoin::Crypto::Constants::sighash_all |
					Bitcoin::Crypto::Constants::sighash_anyonecanpay
			)
			],
			$expected, 'digest ok';
	};
};

subtest 'should digest transactions - native segwit' => sub {

	subtest 'should digest SIGHASH_ALL' => sub {

		# from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh

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
};

subtest 'should digest transactions - compat segwit' => sub {

	subtest 'should digest SIGHASH_ALL' => sub {

		# from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh

		$tx = btc_transaction->from_serialized(
			[
				hex =>
					'0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000'
			]
		);

		$tx->inputs->[0]->set_signature_script([hex => '16001479091972186c449eb1ded22b78e40d009bdf0089']);

		my $expected =
			'01000000b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001976a91479091972186c449eb1ded22b78e40d009bdf008988ac00ca9a3b00000000feffffffde984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c839204000001000000';

		is to_format [hex => $tx->get_digest(signing_index => 0)], $expected, 'digest ok';
	};
};

done_testing;

