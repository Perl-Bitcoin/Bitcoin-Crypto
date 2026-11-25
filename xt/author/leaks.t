use Test2::V0;
use Bitcoin::Crypto qw(:all);
use Bitcoin::Crypto::Util qw(generate_mnemonic);
use Bitcoin::Crypto::Constants qw(:all);

use lib 't/lib';
use TransactionStore;

use constant HAS_TEST_MEMORYGROWTH => eval { require Test::MemoryGrowth; 1 };
plan skip_all => 'This test requires Test::MemoryGrowth module'
	unless HAS_TEST_MEMORYGROWTH;

################################################################################
# This tests whether Bitcoin::Crypto leaks memory in some general scenarios
################################################################################

Test::MemoryGrowth::no_growth {
	my $extprv = btc_extprv->from_mnemonic(generate_mnemonic);
	my $extpub = $extprv->derive_key_bip44(purpose => BIP44_TAPROOT_PURPOSE, get_account => 1)->get_public_key;
	my $final_extpub = $extpub->derive_key_bip44(get_from_account => 1);

	my $prv = $extprv->derive_key_bip44(purpose => BIP44_TAPROOT_PURPOSE)->get_basic_key;
	my $pub = $final_extpub->get_basic_key;

	die 'bad derivation' unless $prv->get_public_key->to_serialized eq $pub->to_serialized;

	my $address = $pub->get_address;
}
calls => 100, 'operations on keys do not leak';

Test::MemoryGrowth::no_growth {
	my $script = btc_script->new
		->add('OP_10')
		->add('OP_ADD')
		->add('OP_16')
		->add('OP_NUMEQUAL');

	my $runner = $script->run(["\x06"]);
	die 'bad script run' unless $runner->success;

	my $address = $script->get_segwit_address;
}
calls => 100, 'operations on scripts do not leak';

# same transaction as t/Taproot/live-transactions.t
Test::MemoryGrowth::no_growth {
	my $tx = btc_transaction->from_serialized(
		[
			hex =>
				'02000000000104e5b5819549e2d93193add6ff17dc260ccbe0614b18f3d37ec3c0c1442d4400c50000000000ffffffffe5b5819549e2d93193add6ff17dc260ccbe0614b18f3d37ec3c0c1442d4400c50100000000ffffffff3c8a4de56f29c76132ef87826a13c87ccb3f092c71565c18fdedfa183f4a15200000000000ffffffffe5b5819549e2d93193add6ff17dc260ccbe0614b18f3d37ec3c0c1442d4400c50200000000ffffffff06b0040000000000002251203d9331d806e265a18aef2177974c457ba423a2228c8030810fcb23410b9d86a122020000000000002251203d9331d806e265a18aef2177974c457ba423a2228c8030810fcb23410b9d86a11b13130000000000225120c5f7f49d4177d09042686dcb7651393acc86d71773f53835e6aec1f59b40605458020000000000002251203d9331d806e265a18aef2177974c457ba423a2228c8030810fcb23410b9d86a158020000000000002251203d9331d806e265a18aef2177974c457ba423a2228c8030810fcb23410b9d86a1be720000000000002251203d9331d806e265a18aef2177974c457ba423a2228c8030810fcb23410b9d86a10140954bb65991c333ae41c73fa22bb4e0605b8507e296277f27eae60815eef7e1db5568115f912992305311351d952921b7948e3e8e4e235e19ac52d23aeefd424a01404ca0e10f2a81fc9c84a56bec30aaaf213ec4a32564313c539c12eb6b56dcd9189aaae5c2ba0c2baa2041c23570c057c51f0c6696350887450c70a86be013a5f701411426961d0c3f8dcdd6f3f46de65a5ce19814e13be1cb1b24c93eb565ece74960312cdf8e602c4d0169520bce08f23692a8e93df592fe678869152d770276c280830140d644b808859ff900400602470c5f64552a9a9590d687354d1415a502099b4fb1286907cc0fba1ac0b300779000203f1f351ad59f7e8e2e2fa02ee1a7ad5f3ec900000000'
		]
	);

	$tx->verify;
}
calls => 100, 'verifying transactions does not leak';

done_testing;

