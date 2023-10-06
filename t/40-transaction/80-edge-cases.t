use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use lib 't/lib';

use Bitcoin::Crypto qw(btc_script btc_transaction btc_prv btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Constants;
use Crypt::Digest::SHA256 qw(sha256);
use TransactionStore;

my $tx;
my $prv = btc_prv->from_serialized("\x12" x 32);

subtest 'should checksig a non-standard transaction' => sub {
	$tx = btc_transaction->new;

	btc_utxo->new(
		txid => [hex => '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'],
		output_index => 0,
		output => {
			locking_script => btc_script->new
				->add('OP_CHECKSIG')
				->add('OP_BOOLAND'),
			value => 1_00000000,
		},
	)->register;

	$tx->add_input(
		utxo => [[hex => '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'], 0],
	);

	$tx->add_output(
		value => 1_00000000,
		locking_script => [
			P2PKH => $prv->get_public_key->get_legacy_address,
		],
	);

	# Manual signing
	my $input = $tx->inputs->[0];
	my $sighash = Bitcoin::Crypto::Constants::sighash_none;
	my $digest = $tx->get_digest(
		signing_index => 0,
		signing_subscript => $input->utxo->output->locking_script->to_serialized,
		sighash => $sighash,
	);
	my $signature = $prv->sign_message($digest);
	$signature .= pack 'C', $sighash;
	$input->signature_script
		->push("\x01")
		->push($signature)
		->push($prv->get_public_key->to_serialized);

	lives_ok { $tx->verify } 'input verification ok';
};

subtest 'should not allow input value smaller than output' => sub {

	# reuse previous $tx

	$tx->add_output(
		value => 1,
		locking_script => [
			P2PKH => $prv->get_public_key->get_legacy_address,
		],
	);

	throws_ok {
		$tx->verify
	} 'Bitcoin::Crypto::Exception::Transaction';

	like $@, qr/value exceeds input/, 'error message ok';
};

subtest 'should serialize and deserialize mixed segwit txs' => sub {

	my $txid = '76899e00277359a639ae138759a1363ceb7a230fea5f9a6bf8c573f7c61706fd';
	my $serialized =
		'02000000000102627f87d7c58472afbd39c66f760216c503a66c343bb217aed8d912fa5b961b42000000001716001432362516c52a861389ff36ef2e259cc4bb794e41feffffff783ea5c926187509911114fbc0bd3c125fce27a47b6ed7882e8a2dd1d8cc8625000000006b483045022100dd79ce31a697fa2f7fd2ac6f6c5a195a9973e53286b81188947ddeb488a7db7602207fad683c86e6786a578fe66523021c2e0a2229492efc17d92a8179bcb27eb505012102fb9d634f6a4cd428d915de6cdcd1d56c66799fe30f3bfe2c5bbea7e42b1c0486feffffff0220ed11010000000017a914392b0579ae8f68973aa56df970f2999b2b6ed13e8755430d00000000001976a91432d7092dab6128aac94964f3f99c08236b9f666988ac0248304502210093048418636fb435513456481edffd171df2d8feadf3a1674cb805089a5905bc02206cc2481342b4daac8bf0441c85d94c382208d650c5e9316586f5d260be3dbe5b0121030a3e29d736f681922e0b21f55f1370cc45a5d9a8c0d7e06cf95110d0b02bf643001ea10700';

	$tx = btc_transaction->from_serialized([hex => $serialized]);
	is to_format [hex => $tx->get_hash], $txid, 'txid ok';

	is_deeply
		to_format [hex => $tx->inputs->[0]->witness->[0]],
		'304502210093048418636fb435513456481edffd171df2d8feadf3a1674cb805089a5905bc02206cc2481342b4daac8bf0441c85d94c382208d650c5e9316586f5d260be3dbe5b01',
		'input 0 witness 0 ok';

	is_deeply
		to_format [hex => $tx->inputs->[0]->witness->[1]],
		'030a3e29d736f681922e0b21f55f1370cc45a5d9a8c0d7e06cf95110d0b02bf643',
		'input 0 witness 1 ok';

	is_deeply $tx->inputs->[1]->witness, [], 'input 1 witness ok';

	is to_format [hex => $tx->to_serialized], $serialized, 'serialization ok';
};

subtest 'should handle NULLDATA outputs' => sub {
	my $txid = 'd29c9c0e8e4d2a9790922af73f0b8d51f0bd4bb19940d9cf910ead8fbe85bc9b';
	btc_utxo->new(
		txid => [hex => $txid],
		output_index => 0,
		output => {
			locking_script => [NULLDATA => 'rickroll'],
			value => 0,
		},
	)->register;

	throws_ok {
		btc_utxo->get(
			[hex => $txid], 0
		);
	} 'Bitcoin::Crypto::Exception::UTXO';
};

subtest 'should correctly handle extra SIGHASH_SINGLE inputs' => sub {
	local $TODO = 'unable to implement yet';

	# from https://bitcointalk.org/index.php?topic=260595.0
	# (verify previous transaction as well just for completeness)

	btc_utxo->extract(
		[
			hex =>
				'0100000003890796106f0553b8c72250ba6f299729f0d87a4022d999c2ad1cfb6480868c1a010000006b483045022100bcbf86c5b928464e070a685ad92775b037dd3dd31eee0f87b25b2909332444ea02203646e18560d05c45141e8a29201ce08c3f2b8b3cdea3b95213df96f513111b4f012103369315cefa93c59eac4ea233d43ed88d4317397ee4acabc87162989e205f289bffffffff7a62583ef04e1d1ee7401cd325a7047c3017aa962a714e3e78789b27e7ed36ae000000006a47304402200488d4b8e0c2d3b6c927e4e781f7815dfedca87627df22fe2edf54afaedcb43002204b2e0b857ea1a2e872709418aaf3e770cf9fde54ff580d9ef6241bbd50998c8a0121025d4dc243b6be5b26635bb712044685090d2f001cfc894d8010547664152bd35dffffffffa8ef17fd4a92662d3dbd7752fb65f711b561a614cf07e299d6bc52a20603a03d000000006a473044022043de896d1ae8018a329f4b0d36f1e4046da38d9863f0a69609ccefa199bc5a92022052697743c01999da0511e7200ba1d8557e8fbc61de25903d8b91ac2f5ff38dcf0121025d4dc243b6be5b26635bb712044685090d2f001cfc894d8010547664152bd35dffffffff021a900500000000001976a9145bd06ce6f075ebfe46ed56b0c09e9761d0feb1d288ac80969800000000001976a914ce279c14623db16f99127e902c1f588a7c58387188ac00000000'
		]
	);

	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'01000000012d51fdc75a26ff3c6138020e1a9bb40f1fab6e39ce96feae3218c9ae035e00ab010000006b483045022100e4f1a521907e50fc44d33132ee98c9715a64df9d2c2860e3e0474c521ab8537e022030af8d3506a5352e2b056445acd855a42d37270e94a629a7b28b21870ec6d761012103808c493f061990d2be001e40f048ae8870320b74895ce2d9652f3c1c73cd6f2cffffffff02f0874b00000000001976a914fcc9b36d38cf55d7d5b4ee4dddb6b2c17612f48c88acf0874b00000000001976a91433cef61749d11ba2adf091a5e045678177fe3a6d88ac00000000'
		]
	);

	lives_ok {
		$tx->verify;
	} 'previous transaction verified ok';

	$tx->update_utxos;
	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'0100000002dc38e9359bd7da3b58386204e186d9408685f427f5e513666db735aa8a6b2169000000006a47304402205d8feeb312478e468d0b514e63e113958d7214fa572acd87079a7f0cc026fc5c02200fa76ea05bf243af6d0f9177f241caf606d01fcfd5e62d6befbca24e569e5c27032102100a1a9ca2c18932d6577c58f225580184d0e08226d41959874ac963e3c1b2feffffffffdc38e9359bd7da3b58386204e186d9408685f427f5e513666db735aa8a6b2169010000006b4830450220087ede38729e6d35e4f515505018e659222031273b7366920f393ee3ab17bc1e022100ca43164b757d1a6d1235f13200d4b5f76dd8fda4ec9fc28546b2df5b1211e8df03210275983913e60093b767e85597ca9397fb2f418e57f998d6afbbc536116085b1cbffffffff0140899500000000001976a914fcc9b36d38cf55d7d5b4ee4dddb6b2c17612f48c88ac00000000'
		]
	);

	lives_ok {
		$tx->verify;
	} 'this transaction verified ok';
};

subtest 'should not verify segwit transactions with uncompressed public keys (P2WPKH)' => sub {
	$prv->set_compressed(0);

	my $random_txid = sha256($prv->to_serialized);
	btc_utxo->new(
		txid => $random_txid,
		output_index => 0,
		output => {
			locking_script => [P2WPKH => $prv->get_public_key->get_segwit_address],
			value => 11,
		},
	)->register;

	$tx = btc_transaction->new;

	$tx->add_input(
		utxo => [$random_txid, 0],
	);

	$tx->add_output(
		locking_script => [P2SH => $prv->get_public_key->get_compat_address],
		value => $tx->fee - 1,
	);

	$prv->sign_transaction($tx, signing_index => 0);

	throws_ok {
		$tx->verify
	} 'Bitcoin::Crypto::Exception::TransactionScript';

	like $@, qr/compressed/, 'error string ok';
};

subtest 'should not verify segwit transactions with uncompressed public keys (P2WSH)' => sub {
	$prv->set_compressed(0);
	my $other_prv = btc_prv->from_serialized("\x13" x 32);

	my $redeem_script = btc_script->from_standard(
		P2MS => [
			1,
			$other_prv->get_public_key->to_serialized,
			$prv->get_public_key->to_serialized,
		]
	);

	my $random_txid = sha256($other_prv->to_serialized);
	btc_utxo->new(
		txid => $random_txid,
		output_index => 0,
		output => {
			locking_script => [P2WSH => $redeem_script->get_segwit_address],
			value => 11,
		},
	)->register;

	$tx = btc_transaction->new;

	$tx->add_input(
		utxo => [$random_txid, 0],
	);

	$tx->add_output(
		locking_script => [P2SH => $prv->get_public_key->get_compat_address],
		value => $tx->fee - 1,
	);

	$other_prv->sign_transaction($tx, redeem_script => $redeem_script, signing_index => 0, multisig => [1, 1]);

	throws_ok {
		$tx->verify
	} 'Bitcoin::Crypto::Exception::TransactionScript';

	like $@, qr/compressed/, 'error string ok';
};

subtest 'should not allow to create transactions using incorrect network addresses' => sub {
	throws_ok {
		btc_script->from_standard(P2WPKH => 'tb1q4grq3j35ggjcsr9psf3hx86ydfczdn77r7e63s');
	} 'Bitcoin::Crypto::Exception::NetworkCheck';
};

done_testing;

