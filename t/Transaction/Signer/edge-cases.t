use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_tapscript btc_script_tree btc_transaction btc_utxo);
use Bitcoin::Crypto::Constants qw(:script);

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

done_testing;

