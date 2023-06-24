use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);

my $tx;

my $payout_script = btc_script->new
	->add('OP_3')
	->push([hex => '02002a57268073cbc5472d35d8f8fae2c52825241592f53e53ae516913d8c82bd1'])
	->push([hex => '026c1061b95ccfc52594c9b376382e2f0240a523b3b1dc5db6a9cdd9730a4a0c21'])
	->push([hex => '029e8c3ae6c0516df4075089ab9475c9335985569ac0f3b9f1a4b0d946785937cd'])
	->push([hex => '02c6a7c72de9221cba7029f1b920a86bb84997d9c91a2e4428b1397cba669dd316'])
	->push([hex => '03ba7c7d7b8d2379de450441445c30a638c555305cbe044abb88f10643d9621bf0'])
	->add('OP_5')
	->add('OP_CHECKMULTISIG')
	;

btc_utxo->new(
	txid => [hex => '105025e0b2b9c3750289d2bd2173e7c4d38826c5b3112696f1a2588bfc0814ac'],
	output_index => 0,
	output => {
		locking_script => [P2SH => $payout_script->get_legacy_address],
		value => 1_00000000,
	},
)->register;

subtest 'should verify multisig transactions (P2SH)' => sub {
	$tx = btc_transaction->new(
		version => 2,
		locktime => 601858,
	);

	my $expected_txid = '78c93aaa2f7fbcf08c528a0dcb691393e50446d71eef30ac5baa0183df33a5b9';

	$tx->add_input(
		utxo => [[hex => '105025e0b2b9c3750289d2bd2173e7c4d38826c5b3112696f1a2588bfc0814ac'], 0],
		signature_script => btc_script->new
			->add('OP_0')
			->push(
				[
					hex =>
					'30440220576976125dfb46f9d617f41b1d8f3c666ae1107610ad910a627cb3eaf18705fc0220219e462d580eb66bf3d4d4d2fbd7f0164d340d23ddf90b82f858b2d3f0ce66bb01'
				]
			)
			->push(
				[
					hex =>
					'3044022001c668407ebcfcea5c5eb406090c2946f6a91bd9881501e834924c2c4e8f588002207f12bdefe185390f28673b95da88b48222fb681c3b1f45083cde814a416e866a01'
				]
			)
			->push(
				[
					hex =>
					'3045022100db620adb2687098ab9961780a76782ccb0241e75882218ff3be8bb99de09fe3502206c929b3cb1c4f289619f9a6cde83caa41a33d2de230d74c11903b48a5fa3bc0301'
				]
			)
			->push($payout_script->to_serialized),
		sequence_no => 0xfffffffd,
	);

	$tx->add_output(
		value => 99987088,
		locking_script => [P2SH => '39zAv4u6QBSmUAttAUP6bLvENRMZuNAJaP'],
	);

	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	lives_ok { $tx->verify } 'input verification ok';
};

subtest 'should not verify incorrect multisig transactions (P2SH)' => sub {
	plan skip_all => 'this test requires implemented P2SH to pass';

	$tx = btc_transaction->new(
		version => 2,
		locktime => 601858,
	);

	# NOTE: modified (incorrect) third signature is given
	$tx->add_input(
		utxo => [[hex => '105025e0b2b9c3750289d2bd2173e7c4d38826c5b3112696f1a2588bfc0814ac'], 0],
		signature_script => btc_script->new
			->add('OP_0')
			->push(
				[
					hex =>
					'30440220576976125dfb46f9d617f41b1d8f3c666ae1107610ad910a627cb3eaf18705fc0220219e462d580eb66bf3d4d4d2fbd7f0164d340d23ddf90b82f858b2d3f0ce66bb01'
				]
			)
			->push(
				[
					hex =>
					'3044022001c668407ebcfcea5c5eb406090c2946f6a91bd9881501e834924c2c4e8f588002207f12bdefe185390f28673b95da88b48222fb681c3b1f45083cde814a416e866a01'
				]
			)
			->push(
				[
					hex =>
					'3045022100db620adb2687098ab9961780a76782ccb0241e75882218ff3be8bb99de09fe3502206c929b3cb1c4f289619f9a6cde83caa41a33d2de230d74c11903b48a5fa3bc0f01'
				]
			)
			->push($payout_script->to_serialized),
		sequence_no => 0xfffffffd,
	);

	$tx->add_output(
		value => 99987088,
		locking_script => [P2SH => '39zAv4u6QBSmUAttAUP6bLvENRMZuNAJaP'],
	);

	# NOTE: modified signature - no txid test
	dies_ok { $tx->verify } 'input verification ok';
};

done_testing;

