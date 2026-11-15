use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_pub btc_transaction btc_script_tree btc_tapscript btc_utxo);
use Bitcoin::Crypto::Util qw(lift_x);
use Bitcoin::Crypto::Constants qw(:script);

my $prv = btc_prv->from_serialized("\x01" x 32);
my $pub = $prv->get_public_key;
my $pub2 = btc_pub->from_serialized(lift_x "\x02" x 32);

subtest 'should check control block data for unknown leaf versions' => sub {
	my $script = btc_tapscript->new->add('OP_CHECKSIGADD');
	my $tree = btc_script_tree->new(
		tree => [
			{
				id => 'test leaf',
				leaf_version => 0xfe,    # random unknown leaf version
				script => $script,
			}
		]
	);

	my $utxo = btc_utxo->new(
		txid => "\x07" x 32,
		output_index => 0,
		output => {
			value => 1000,
			locking_script => [address => $pub->get_taproot_address($tree)],
		}
	);

	# build tx from scratch
	my $tx = btc_transaction->new(version => 2);
	$tx->add_input(utxo => $utxo);
	$tx->add_output(
		value => 1000,
		locking_script => [address => $pub->get_taproot_address],
	);

	# NOTE: a different public key is used
	$tx->sign(
		signing_index => 0,
		script_tree => $tree,
		leaf_id => 'test leaf',
		public_key => $pub2,
		)
		->add_bytes([hex => 'feedbeef'])
		->finalize;

	# try verifying - should fail
	my $ex = dies { $tx->verify };
	isa_ok $ex, 'Bitcoin::Crypto::Exception::TransactionScript';
	like $ex, qr{\Qinvalid public key or control block\E}, 'fail reason ok';

	# re-sign, use correct public key this time
	$tx->sign(
		signing_index => 0,
		script_tree => $tree,
		leaf_id => 'test leaf',
		public_key => $pub,
		)
		->add_bytes([hex => 'feedbeef'])
		->finalize;

	ok lives { $tx->verify }, 'verification with proper public key ok (script is never run)';
};

subtest 'should not check sighash for an unknown pubkey type' => sub {
	my $script = btc_tapscript->new->push("\x00\x01\x02")->add('OP_CHECKSIG');    # simulating an unknown key type
	my $tree = btc_script_tree->new(
		tree => [
			{
				id => 'test leaf',
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => $script,
			}
		]
	);

	my $utxo = btc_utxo->new(
		txid => "\x07" x 32,
		output_index => 0,
		output => {
			value => 1000,
			locking_script => [address => $pub->get_taproot_address($tree)],
		}
	);

	# build tx from scratch
	my $tx = btc_transaction->new(version => 2);
	$tx->add_input(utxo => $utxo);
	$tx->add_output(
		value => 1000,
		locking_script => [address => $pub->get_taproot_address],
	);

	$tx->sign(
		signing_index => 0,
		script_tree => $tree,
		leaf_id => 'test leaf',
		public_key => $pub,
		)
		->add_bytes(("\x01" x 64) . "\xff")    # this is an invalid sighash normally
		->finalize;

	# verification succeeds because the signature should never be checked
	ok lives { $tx->verify }, 'verification successful';
};

done_testing;

