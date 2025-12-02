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
		locking_script => [P2WPKH => $pub1->get_segwit_address],
		value => 1000
	},
);

my $utxo2 = btc_utxo->new(
	txid => "\x01" x 32,
	output_index => 1,
	output => {
		locking_script => [P2WSH => $script->get_segwit_address],
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

# P2WPKH output
$tx
	->sign(
		signing_index => 0,
	)
	->add_signature(
		$priv1,
		sighash => SIGHASH_ALL | SIGHASH_ANYONECANPAY
	)
	->finalize;

# P2WSH output
$tx
	->sign(
		signing_index => 1,
		script => $script,
	)
	->add_signature('')
	->add_signature($priv2, sighash => SIGHASH_NONE)
	->finalize;

ok lives { $tx->verify }, 'transaction verification ok';

done_testing;

