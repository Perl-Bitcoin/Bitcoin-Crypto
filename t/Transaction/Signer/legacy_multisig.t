use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Constants qw(:sighash);

my $priv1 = btc_prv->from_serialized("\x01" x 32);
my $priv2 = btc_prv->from_serialized("\x02" x 32);

my $pub1 = $priv1->get_public_key;
my $pub2 = $priv2->get_public_key;

my $script = btc_script->new
	->push_number(2)
	->push($pub1->to_serialized)
	->push($pub2->to_serialized)
	->push_number(2)
	->add('OP_CHECKMULTISIG');

my $utxo1 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 0,
	output => {
		locking_script => $script,
		value => 1000
	},
);

my $utxo2 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 1,
	output => {
		locking_script => [P2SH => $script->get_legacy_address],
		value => 1000
	},
);

my $tx = btc_transaction->new;

$tx->add_input(utxo => $utxo1);
$tx->add_input(utxo => $utxo2);

$tx->add_output(
	locking_script => [P2PKH => $pub2->get_legacy_address],
	value => 2000
);

# custom script (not P2SH)
$tx
	->sign(
		signing_index => 0,
	)
	->add_signature($priv2)
	->add_signature(
		[
			hex =>
			'30440220353362c57931db260ea62aa98718d5f01e9512b0443a5fc01dd54322adb9cc9e022001cb0d83f2e5c5bf390cdd524181abf1af7c5bc10babd74477c36ed23b15ef4702'
		]
	)
	->finalize_multisignature
	->finalize;

# P2SH output
$tx
	->sign(
		signing_index => 1,
		script => $script,
	)
	->add_signature(
		[
			hex =>
			'304402206ef02f993aa36743f2e38261e73721e8ea61eee68c9789b5b13321f3f22bb15a02203064f3d456d11a0181505a524aa9c3f639d87878daaab1177db9039a57309a3d01'
		]
	)
	->add_signature($priv1, sighash => SIGHASH_SINGLE)
	->finalize_multisignature
	->finalize;

ok lives { $tx->verify }, 'transaction verification ok';

done_testing;

