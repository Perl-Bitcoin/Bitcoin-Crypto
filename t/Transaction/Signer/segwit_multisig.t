use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Constants qw(:sighash);

my $priv1 = btc_prv->from_serialized("\x01" x 32);
my $priv2 = btc_prv->from_serialized("\x02" x 32);

my $pub1 = $priv1->get_public_key;
my $pub2 = $priv2->get_public_key;

# random script with two sigops, an if and a codeseparator
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
		locking_script => [P2WSH => $script->get_segwit_address],
		value => 1000
	},
);

my $utxo2 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 1,
	output => {
		locking_script => [P2SH => $script->get_compat_address],
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

# native output
$tx
	->sign(
		signing_index => 0,
		script => $script,
	)
	->add_signature($priv2)
	->add_signature(
		[
			hex =>
			'3045022100df91dadbe6557f765d99ca594f89cb5c5a6b3a27aa6aa98bc79258695ae6c39e0220409f1517012e76d95805564e600a6d32f626da5182886d985a26b1b0b483705581'
		]
	)
	->finalize_multisignature
	->finalize;

# compat output
$tx
	->sign(
		signing_index => 1,
		script => $script,
		compat => !!1,
	)
	->add_signature(
		[
			hex =>
			'304402207795898cc932a2e4dd1fca886b5489cf418eb1b981ba8d78f6ab4ad85895fe800220670158e44f79bf2b795adf11cdf2a0c91fee6bdca55fb54543a02f4f7dda504001'
		]
	)
	->add_signature(
		$priv1,
		sighash => SIGHASH_ALL | SIGHASH_ANYONECANPAY
	)
	->finalize_multisignature
	->finalize;

ok lives { $tx->verify }, 'transaction verification ok';

done_testing;

