use Test2::V0;
use Bitcoin::Secp256k1;
use Bitcoin::Crypto qw(btc_prv btc_pub btc_transaction btc_script_tree btc_tapscript);
use Bitcoin::Crypto::Util qw(lift_x to_format get_taproot_ext);

use lib 't/lib';
use TransactionStore;

# disable randomness for deterministic signatures
$Bitcoin::Secp256k1::FORCED_SCHNORR_AUX_RAND = "\x00" x 32;

# these examples were provided by https://learnmeabitcoin.com/technical/upgrades/taproot/
my $prv_raw = '55d7c5a9ce3d2b15a62434d01205f3e59077d51316f5c20628b3a4b8b2a76f4c';
my $pub_raw = '924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329';

my $prv = btc_prv->from_serialized([hex => $prv_raw]);
my $pub = btc_pub->from_serialized(lift_x [hex => $pub_raw]);

subtest 'should sign/verify key path spend case' => sub {

	# check address
	is $pub->get_address, 'bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf', 'address ok';

	# build tx from scratch
	my $tx = btc_transaction->new(version => 2);
	$tx->add_input(utxo => [[hex => 'a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec'], 0]);
	$tx->add_output(
		value => 10_000,
		locking_script => [address => 'bc1qfezv57fvu4z6ew5e6sfsg3sd686nhcuyt8ukve'],
	);
	is to_format [hex => $tx->get_hash], '091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe',
		'transaction hash ok';

	# try signing
	$prv->sign_transaction($tx, signing_index => 0, sighash => Bitcoin::Crypto::Constants::sighash_all);
	is [map { to_format [hex => $_] } @{$tx->inputs->[0]->witness}], [
		'b693a0797b24bae12ed0516a2f5ba765618dca89b75e498ba5b745b71644362298a45ca39230d10a02ee6290a91cebf9839600f7e35158a447ea182ea0e022ae01'
		],
		'witness ok';

	# try verifying
	ok lives { $tx->verify };
};

subtest 'should sign/verify simple script path spend case' => sub {
	my $script = btc_tapscript->from_serialized([hex => '5887']);
	my $tree = btc_script_tree->new(
		tree => [
			{
				id => 0,
				leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
				script => $script,
			}
		]
	);

	# check address
	is $pub->get_taproot_address($tree), 'bc1prwh247gy0nzzq4dr0gavnqda7l66h9h66rfdqlz5vz8g5xqmj3msh7uxx0',
		'address ok';

	# build tx from scratch
	my $tx = btc_transaction->new(version => 2);
	$tx->add_input(utxo => [[hex => '44d275a5364b2430e7a8aa76d4b3235380fef79cf663dc544889c33208a20dc2'], 0]);
	$tx->add_input(utxo => [[hex => '8bc4f8facaaf7c4bdf6d77fac90aea208c2099a091d4b09658d002739daaad87'], 1]);
	$tx->add_output(
		value => 3599,
		locking_script => [address => 'bc1qj2uv8ft04sfpmhxll0y9kqhmnmmgzqu2zplyzu'],
	);
	is to_format [hex => $tx->get_hash], '5ff05f74d385bd39e344329330461f74b390c1b5ead87c4f51b40c555b75719d',
		'transaction hash ok';

	# manual signing (custom script)
	# script with witness must be OP_8 OP_8 OP_EQUAL
	my $input_witness = [];
	$tx->inputs->[1]->set_witness($input_witness);
	push @$input_witness, "\x08";
	push @$input_witness, $script->to_serialized;
	push @$input_witness, $tree->get_control_block(0, $pub)->to_serialized;
	is [map { to_format [hex => $_] } @{$tx->inputs->[1]->witness}], [
		'08',
		'5887',
		'c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329',
		],
		'witness ok';

	# manually fill the witness of other input (unknown private key)
	$tx->inputs->[0]->set_witness(
		[
			[
				hex =>
					'304402200c4c0bfe93f6622fa0790b6d28bf755c1a3f23e8404bb804ca8e2db080b613b102205bcf0a4e4559ba9b40e6b174cf91af061dfa21691923b410e351326708b041a001'
			],
			[hex => '030c7196376bc1df61b6da6ee711868fd30e370dd273332bfb02a2287d11e2e9c5'],
		]
	);

	# try verifying
	ok lives { $tx->verify };
};

subtest 'should sign/verify script path spend case with signature' => sub {
	my $script_prv =
		btc_prv->from_serialized([hex => '9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189']);
	$script_prv->set_taproot_output(!!1);

	my $script = btc_tapscript->new
		->push($script_prv->get_public_key->get_xonly_key)
		->add('OP_CHECKSIG');

	my $tree = btc_script_tree->new(
		tree => [
			{
				id => 0,
				leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
				script => $script,
			}
		]
	);

	# check address
	is $pub->get_taproot_address($tree), 'bc1p7dmcmml9zuafhackj463zc3yl9suq0rjts8f3wx63u2a72gefwqqku46c7',
		'address ok';

	# build tx from scratch
	my $tx = btc_transaction->new(version => 2);
	$tx->add_input(utxo => [[hex => 'd1c40446c65456a9b11a9dddede31ee34b8d3df83788d98f690225d2958bfe3c'], 0]);
	$tx->add_output(
		value => 15000,
		locking_script => [address => 'bc1qphn5thzcmrnzum68hh3se4vqf2pqzmu7hl34z0'],
	);
	is to_format [hex => $tx->get_hash], '797505b104b5fb840931c115ea35d445eb1f64c9279bf23aa5bb4c3d779da0c2',
		'transaction hash ok';

	# manual signing (custom script)
	my $input_witness = [];
	$tx->inputs->[0]->set_witness($input_witness);
	push @$input_witness, $script_prv->sign_message(
		$tx->get_digest(
			signing_index => 0,
			signing_subscript => $script->to_serialized,
			taproot_ext_flag => 1,
			taproot_ext => get_taproot_ext(1, script_tree => $tree, leaf_id => 0),
			sighash => Bitcoin::Crypto::Constants::sighash_all,
		)
	) . pack('C', Bitcoin::Crypto::Constants::sighash_all);
	push @$input_witness, $script->to_serialized;
	push @$input_witness, $tree->get_control_block(0, $pub)->to_serialized;

	is [map { to_format [hex => $_] } @{$tx->inputs->[0]->witness}], [
		'01769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01',
		'206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac',
		'c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329',
		],
		'witness ok';

	# try verifying
	ok lives { $tx->verify };
};

subtest 'should sign/verify script path spend case with tree' => sub {
	my $script = btc_tapscript->new
		->add('OP_3')
		->add('OP_EQUAL');

	my $tree = btc_script_tree->new(
		tree => [
			[
				[
					[
						{
							leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
							script => btc_tapscript->from_serialized([hex => '5187']),
						},
						{
							leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
							script => btc_tapscript->from_serialized([hex => '5287']),
						}
					],
					{
						id => 0,
						leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
						script => $script,
					}
				],
				{
					leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
					script => btc_tapscript->from_serialized([hex => '5487']),
				}
			],
			{
				leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
				script => btc_tapscript->from_serialized([hex => '5587']),
			}
		]
	);

	# check address
	is $pub->get_taproot_address($tree), 'bc1pj7w0lxtrdksmpeylsug4znry9ajq68myxsxr0py5y2trdrad6zjsrfwpyj',
		'address ok';

	# build tx from scratch
	my $tx = btc_transaction->new(version => 2);
	$tx->add_input(utxo => [[hex => 'ec7b0fdfeb2c115b5a4b172a3a1cf406acc2425229c540d40ec752d893aac0d7'], 0]);
	$tx->add_output(
		value => 294,
		locking_script => [address => 'bc1qj2uv8ft04sfpmhxll0y9kqhmnmmgzqu2zplyzu'],
	);
	is to_format [hex => $tx->get_hash], '992af7eb67f37a4dfaa64ea6f03a70c35b6063ba5ee3fe41734c3460b4006463',
		'transaction hash ok';

	# manual signing (custom script)
	# script with witness must be OP_3 OP_3 OP_EQUAL
	my $input_witness = [];
	$tx->inputs->[0]->set_witness($input_witness);
	push @$input_witness, "\x03";
	push @$input_witness, $script->to_serialized;
	push @$input_witness, $tree->get_control_block(0, $pub)->to_serialized;

	is [map { to_format [hex => $_] } @{$tx->inputs->[0]->witness}], [
		'03',
		'5387',
		'c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a33291324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f',
		],
		'witness ok';

	# try verifying
	ok lives { $tx->verify };
};

done_testing;

