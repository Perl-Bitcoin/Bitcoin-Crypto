use Test2::V0;
use Bitcoin::Crypto qw(btc_pub btc_transaction btc_tapscript btc_script_tree);
use Bitcoin::Crypto::Util qw(to_format lift_x);
use Bitcoin::Crypto::Constants qw(:script);
use Encode qw(encode);

use utf8;

use lib 't/lib';
use TransactionStore;

# this constructs live transaction from scratch. Transaction id is
# 2eb8dbaa346d4be4e82fe444c2f0be00654d8cfd8c4a9a61b11aeaab8c00b272
#
# signatures are inserted as constants, since we don't know the private key.
# However, tapscript, script tree and control block are built normally.

# both inputs use identical scripts
my $script = btc_tapscript->new
	->push([hex => 'c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabae'])
	->add('OP_CHECKSIG')
	->push([hex => 'b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333c'])
	->add('OP_CHECKSIGADD')
	->add('OP_1')
	->add('OP_NUMEQUAL');

# tree seems to have only one leaf
my $tree = btc_script_tree->new(
	tree => [
		{
			id => 0,
			leaf_version => TAPSCRIPT_LEAF_VERSION,
			script => $script,
		}
	]
);

# this is not a taproot output key yet
my $pubkey =
	btc_pub->from_serialized(lift_x [hex => '0000000000000000000000000000000000000000000000000000000000000001']);

my $tx = btc_transaction->new;

$tx->add_input(
	utxo => [[hex => '09347a39275641e291dff2d8beded236b6b1bb0f4a6ae40a50f67dce02cf7323'], 0],
	sequence_no => 0xfffffffd,
);

$tx->add_input(
	utxo => [[hex => '777c998695de4b7ecec54c058c73b2cab71184cf1655840935cd9388923dc288'], 0],
	sequence_no => 0xfffffffd,
);

$tx->add_output(
	value => 0,
	locking_script => [NULLDATA => encode 'UTF-8', 'gm taproot 🥕 https://bitcoindevkit.org'],
);

$tx->add_output(
	value => 1154670,
	locking_script => [address => '1Taproote7gvQGKz5g982ecSbPvqJhMUf'],
);

$tx
	->sign(
		signing_index => 0,
		script_tree => $tree,
		leaf_id => 0,
		public_key => $pubkey,
	)
	->add_signature('')
	->add_signature(
		[
			hex =>
			'0adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01'
		]
	)
	->finalize;

$tx
	->sign(
		signing_index => 1,
		script_tree => $tree,
		leaf_id => 0,
		public_key => $pubkey,
	)
	->add_signature('')
	->add_signature(
		[
			hex =>
			'4636070d21adc8280735383102f7a0f5978cea257777a23934dd3b458b79bf388aca218e39e23533a059da173e402c4fc5e3375e1f839efb22e9a5c2a815b07301'
		]
	)
	->finalize;

my $expected_tx =
	'010000000001022373cf02ce7df6500ae46a4a0fbbb1b636d2debed8f2df91e2415627397a34090000000000fdffffff88c23d928893cd3509845516cf8411b7cab2738c054cc5ce7e4bde9586997c770000000000fdffffff0200000000000000002b6a29676d20746170726f6f7420f09fa5952068747470733a2f2f626974636f696e6465766b69742e6f72676e9e1100000000001976a91405070d0290da457409a37db2e294c1ffbc52738088ac04410adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000104414636070d21adc8280735383102f7a0f5978cea257777a23934dd3b458b79bf388aca218e39e23533a059da173e402c4fc5e3375e1f839efb22e9a5c2a815b07301004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000100000000';

is to_format [hex => $tx->to_serialized], $expected_tx, 'serialized transaction ok';
ok lives { $tx->verify }, 'transaction verified successfully';

done_testing;

