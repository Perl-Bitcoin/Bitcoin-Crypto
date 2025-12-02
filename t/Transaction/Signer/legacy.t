use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Constants qw(:sighash);

my $priv1 = btc_prv->from_serialized("\x01" x 32);
my $priv2 = btc_prv->from_serialized("\x02" x 32);

my $pub1 = $priv1->get_public_key;
my $pub2 = $priv2->get_public_key;

# random script with two sigops, an if and a codeseparator
my $script = btc_script->new
	->push($pub1->to_serialized)
	->add('OP_CHECKSIG')
	->add('OP_NOTIF')
	->add('OP_CODESEPARATOR')
	->push($pub2->to_serialized)
	->add('OP_CHECKSIG')
	->add('OP_ELSE')
	->add('OP_TRUE')
	->add('OP_ENDIF');

my $utxo1 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 0,
	output => {
		locking_script => [P2PKH => $pub2->get_legacy_address],
		value => 1000
	},
);

my $utxo2 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 1,
	output => {
		locking_script => $script,
		value => 1000
	},
);

my $utxo3 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 2,
	output => {
		locking_script => [P2SH => $script->get_legacy_address],
		value => 1000
	},
);

my $tx = btc_transaction->new;

$tx->add_input(utxo => $utxo1);
$tx->add_input(utxo => $utxo2);
$tx->add_input(utxo => $utxo3);

$tx->add_output(
	locking_script => [P2PKH => $pub2->get_legacy_address],
	value => 3000
);

# P2PKH output
$tx
	->sign(
		signing_index => 0,
	)
	->add_signature($priv2, sighash => SIGHASH_SINGLE)
	->finalize;

# custom script (not P2SH)
$tx
	->sign(
		signing_index => 1,
	)
	->add_signature(
		[
			hex =>
			'3045022100f6a085140f873b867d91835a711256e41738e2ab2a17f2a857313ef3766158d20220406d5cefad0e689e186017d8dcb12e065ff53fcac8bb00a8a3f51ee41c9f76da02'
		]
	)
	->finalize;

# P2SH output
$tx
	->sign(
		signing_index => 2,
		script => $script,
	)
	->add_signature('')
	->add_signature($priv2, sighash => SIGHASH_NONE)
	->finalize;

ok lives { $tx->verify }, 'transaction verification ok';

done_testing;

