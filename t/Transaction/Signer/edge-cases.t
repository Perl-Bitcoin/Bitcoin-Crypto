use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_tapscript btc_script_tree btc_transaction btc_utxo);
use Bitcoin::Crypto::Constants qw(:script);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Transaction::Flags;
use Bitcoin::Secp256k1;

# disable randomness for deterministic signatures
$Bitcoin::Secp256k1::FORCED_SCHNORR_AUX_RAND = "\x00" x 32;

my $priv1 = btc_prv->from_serialized("\x01" x 32);
my $priv2 = btc_prv->from_serialized("\x02" x 32);

my $pub1 = $priv1->get_public_key;
my $pub2 = $priv2->get_public_key;

# random tapscript
my $script = btc_tapscript->new
	->push_number(0)
	->add('OP_NUMEQUALVERIFY')
	->push($pub2->get_taproot_output_key->get_xonly_key)
	->add('OP_CHECKSIGVERIFY');

# duplicated script is not a problem - we don't want a tree too flat in this test
my $tree = btc_script_tree->new(
	tree => [
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
);

my $utxo1 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 0,
	output => {
		locking_script => [P2TR => $pub1->get_taproot_address($tree)],
		value => 1000
	},
);

my $tx = btc_transaction->new;

$tx->add_input(utxo => $utxo1);

$tx->add_output(
	locking_script => [P2PKH => $pub2->get_legacy_address],
	value => 1000
);

my $utxo2 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 1,
	output => {
		locking_script => [P2PKH => $pub1->get_legacy_address],
		value => 1000
	},
);

my $tx_legacy = btc_transaction->new;

$tx_legacy->add_input(utxo => $utxo2);

$tx_legacy->add_output(
	locking_script => [P2PKH => $pub2->get_legacy_address],
	value => 1000
);

subtest 'should raise a sign exception on signing error' => sub {
	my $err = dies {
		$tx
			->sign(
				signing_index => 0,
				script_tree => $tree,
				leaf_id => 0,
				public_key => $pub1,
			)
			->add_signature($priv2->get_taproot_output_key)
			->finalize;
	};

	isa_ok $err, 'Bitcoin::Crypto::Exception::Sign';
	like $err, qr{finding next sigop failed};
	like $err, qr{stack error};
};

subtest 'should raise a sign exception on bad step over sigop' => sub {
	my $err = dies {
		$tx
			->sign(
				signing_index => 0,
				script_tree => $tree,
				leaf_id => 0,
				public_key => $pub1,
			)
			->add_number(0)
			->add_signature('')
			->finalize;
	};

	isa_ok $err, 'Bitcoin::Crypto::Exception::Sign';
	like $err, qr{stepping over sigop failed};
	like $err, qr{marked as invalid};
};

subtest 'should not modify signature without finalizing' => sub {
	$tx
		->sign(
			signing_index => 0,
			script_tree => $tree,
			leaf_id => 0,
			public_key => $pub1,
		)
		->add_number(0)
		->add_signature($priv2->get_taproot_output_key);

	ok !@{$tx->inputs->[0]->witness // []}, 'witness empty ok';
};

subtest 'should allow taking signature bytes mid-signing' => sub {
	my $signature = $tx
		->sign(
			signing_index => 0,
			script_tree => $tree,
			leaf_id => 0,
			public_key => $pub1,
		)
		->add_number(0)
		->add_signature($priv2->get_taproot_output_key)
		->signature;

	is [map { to_format [hex => $_] } @$signature], [

		# control block
		'c01b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f5febaae2044a6aff8331965bfa11f7c9f3fd609dc7a1b32dae2b8ec64d5c757b',

		# serialized script
		to_format [hex => $script->to_serialized],

		# OP_0
		'',

		# signature
		'f3ea5fb53d2170c24ff6225e1625285525995f2711ec12b17afe209fedb844170c8255cd35eb6de5df85242bb48782a54d46bf68dab62388c7fbc11770084b97',
		],
		'signature ok';
};

subtest 'should disallow custom sighash value in P2TR' => sub {
	my $err = dies {
		$tx
			->sign(
				signing_index => 0,
				script_tree => $tree,
				leaf_id => 0,
				public_key => $pub1,
			)
			->add_number(0)
			->add_signature($priv2->get_taproot_output_key, sighash => 57)
			->finalize;
	};

	isa_ok $err, 'Bitcoin::Crypto::Exception::Sign';
	like $err, qr{bad sighash};
};

subtest 'should disallow custom sighash value in legacy (with flags)' => sub {
	my $err = dies {
		$tx_legacy
			->sign(
				signing_index => 0,
				flags => {strict_encoding => !!1},
			)
			->add_signature($priv1, sighash => 4)
			->finalize;
	};

	isa_ok $err, 'Bitcoin::Crypto::Exception::Sign';
	like $err, qr{bad sighash};
};

done_testing;

