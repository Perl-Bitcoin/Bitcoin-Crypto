use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use lib 't/lib';

use Bitcoin::Crypto qw(btc_script btc_transaction btc_prv btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Constants;
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
	my $digest = $tx->get_digest(
		signing_index => 0,
		signing_subscript => $input->utxo->output->locking_script->to_serialized,
	);
	my $signature = $prv->sign_message($digest, 'hash256');
	$signature .= pack 'C', Bitcoin::Crypto::Constants::sighash_all;
	$input->signature_script
		->push("\x01")
		->push($signature)
		->push($prv->get_public_key->to_serialized);

	lives_ok { $tx->verify } 'input verification ok';
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

done_testing;

