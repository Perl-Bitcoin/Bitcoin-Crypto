use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_script btc_transaction btc_prv);
use Bitcoin::Crypto::Transaction::UTXO;
use Bitcoin::Crypto::Constants;

my $tx;
my $prv = btc_prv->from_str("\x12" x 32);

subtest 'should checksig a non-standard transaction' => sub {
	$tx = btc_transaction->new;

	Bitcoin::Crypto::Transaction::UTXO->new(
		txid => [hex => '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'],
		output_index => 0,
		output => {
			locking_script => btc_script->new
				->add('OP_CHECKSIG')
				->add('OP_BOOLAND'),
			value => 1_00000000,
		},
	)->register;

	$tx->add_input(
		utxo => [[hex => '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'], 0],
		signature_script => btc_script->new,
	);

	$tx->add_output(
		value => 1_00000000,
		locking_script => [
			P2PKH => $prv->get_public_key->get_legacy_address,
		],
	);

	# Manual signing
	my $input = $tx->inputs->[0];
	my $digest = $tx->get_digest(
		signing_index => 0,
		signing_subscript => $input->utxo->output->locking_script->to_serialized,
	);
	my $signature = $prv->sign_message($digest, 'hash256');
	$signature .= pack 'C', Bitcoin::Crypto::Constants::sighash_all;
	$input->signature_script
		->push("\x01")
		->push($signature)
		->push($prv->get_public_key->to_str);

	lives_ok { $tx->verify } 'input verification ok';
};

done_testing;

