use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_tapscript btc_script_tree btc_transaction btc_utxo);
use Bitcoin::Crypto::Constants qw(:script :sighash);

my $priv1 = btc_prv->from_serialized("\x01" x 32);
my $priv2 = btc_prv->from_serialized("\x02" x 32);

my $pub1 = $priv1->get_public_key;
my $pub2 = $priv2->get_public_key;

# random tapscript
my $script = btc_tapscript->new
	->push_number(0)
	->push($pub1->get_taproot_output_key->get_xonly_key)
	->add('OP_CHECKSIGADD')
	->add('OP_CODESEPARATOR')
	->push($pub2->get_taproot_output_key->get_xonly_key)
	->add('OP_CHECKSIGADD')
	->push_number(1)
	->add('OP_NUMEQUAL');

# duplicated script is not a problem - we don't want a tree too flat in this test
my $tree = btc_script_tree->new(
	tree => [
		[
			{
				id => 0,
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => $script,
			},
			{
				id => 1,
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => $script,
			},
		],
		{
			leaf_version => TAPSCRIPT_LEAF_VERSION,
			script => $script,
		}
	],
);

my $utxo1 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 0,
	output => {
		locking_script => [P2TR => $pub1->get_taproot_address],
		value => 1000
	},
);

my $utxo2 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 1,
	output => {
		locking_script => [P2TR => $pub1->get_taproot_address($tree)],
		value => 1000
	},
);

my $utxo3 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 2,
	output => {
		locking_script => [P2TR => $pub1->get_taproot_address($tree)],
		value => 1000
	},
);

my $utxo4 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 3,
	output => {
		locking_script => [P2TR => $pub1->get_taproot_address($tree)],
		value => 1000
	},
);

my $tx = btc_transaction->new;

$tx->add_input(utxo => $utxo1);
$tx->add_input(utxo => $utxo2);
$tx->add_input(utxo => $utxo3);
$tx->add_input(utxo => $utxo4);

$tx->add_output(
	locking_script => [P2PKH => $pub2->get_legacy_address],
	value => 3000
);

# key path
$tx
	->sign(
		signing_index => 0,
	)
	->add_signature(
		$priv1,
		sighash => SIGHASH_ALL | SIGHASH_ANYONECANPAY
	)
	->finalize;

# key path with tree
$tx
	->sign(
		signing_index => 1,
		script_tree => $tree,
	)
	->add_signature($priv1)
	->finalize;

# script path #0
$tx
	->sign(
		signing_index => 2,
		leaf_id => 0,
		script_tree => $tree,
		public_key => $pub1,
	)
	->add_signature($priv1->get_taproot_output_key, sighash => SIGHASH_ALL)
	->add_signature('')
	->finalize;

# script path #1
$tx
	->sign(
		signing_index => 3,
		leaf_id => 1,
		script_tree => $tree,
		public_key => $pub1,
	)
	->add_signature('')
	->add_signature($priv2->get_taproot_output_key)
	->finalize;

ok lives { $tx->verify }, 'transaction verification ok';

done_testing;

