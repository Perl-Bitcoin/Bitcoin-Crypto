use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use lib 't/lib';

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);
use TransactionStore;

# partial taproot support test script
# (testing support for P2TR creation and recognition)

subtest 'should allow creation of P2TR outputs' => sub {
	my $tx = btc_transaction->new;

	$tx->add_input(
		utxo => [[hex => '464564320917d87c2398ad97b2b9e864fb5dde99f746263cc478bced35415680'], 0],
		signature_script => [
			hex =>
				'483045022100a957c09ad0804499e220907cbe3f1ab8f0dbc0bd4e4acae255c88dd4ecc416ba02202ed19f9d3f41158fcc00c3be82efaa330d8cf2aeea0ddfe277998db65200ab8201210369e03e2c91f0badec46c9c903d9e9edae67c167b9ef9b550356ee791c9a40896'
		],
	);

	$tx->add_output(
		locking_script => [address => '1FWQiwK27EnGXb6BiBMRLJvunJQZZPMcGd'],
		value => 7_45212495,
	);

	$tx->add_output(
		locking_script => [address => 'bc1p9hqnycmek9nejeqj8pjhq24sepsfued79908lxhwtnxhg5g4ck2q8a6zsm'],
		value => 24057000,
	);

	is to_format [hex => $tx->get_hash], 'a8ae6eb5213cac8d7d4cf6a0d955d1099fae621ea0ffb2b0910c08c3fbe9c17a',
		'transaction hash ok';
	lives_ok {
		$tx->verify;
	} 'tx verified ok';
};

subtest 'should recognize P2TR outputs' => sub {
	my $tx = btc_transaction->from_serialized(
		[
			hex =>
				'010000000180564135edbc78c43c2646f799de5dfb64e8b9b297ad98237cd8170932644546000000006b483045022100a957c09ad0804499e220907cbe3f1ab8f0dbc0bd4e4acae255c88dd4ecc416ba02202ed19f9d3f41158fcc00c3be82efaa330d8cf2aeea0ddfe277998db65200ab8201210369e03e2c91f0badec46c9c903d9e9edae67c167b9ef9b550356ee791c9a40896ffffffff024f0a6b2c000000001976a9149f21a07a0c7c3cf65a51f586051395762267cdaf88aca8146f01000000002251202dc1326379b1679964123865702ab0c8609e65be295e7f9aee5ccd745115c59400000000'
		]
	);

	my $output = $tx->outputs->[1];
	is $output->locking_script->type, 'P2TR', 'type recognition ok';
	is $output->locking_script->get_address, 'bc1p9hqnycmek9nejeqj8pjhq24sepsfued79908lxhwtnxhg5g4ck2q8a6zsm',
		'address recognition ok';
};

done_testing;

