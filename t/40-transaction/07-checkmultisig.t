use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use lib 't/lib';

use Bitcoin::Crypto qw(btc_script btc_transaction btc_utxo btc_block);
use Bitcoin::Crypto::Util qw(to_format);
use TransactionStore;

my $tx;

my $redeem_script = btc_script->from_standard(
	P2MS => [
		3,
		[hex => '02002a57268073cbc5472d35d8f8fae2c52825241592f53e53ae516913d8c82bd1'],
		[hex => '026c1061b95ccfc52594c9b376382e2f0240a523b3b1dc5db6a9cdd9730a4a0c21'],
		[hex => '029e8c3ae6c0516df4075089ab9475c9335985569ac0f3b9f1a4b0d946785937cd'],
		[hex => '02c6a7c72de9221cba7029f1b920a86bb84997d9c91a2e4428b1397cba669dd316'],
		[hex => '03ba7c7d7b8d2379de450441445c30a638c555305cbe044abb88f10643d9621bf0'],
	]
);

btc_utxo->new(
	txid => [hex => '105025e0b2b9c3750289d2bd2173e7c4d38826c5b3112696f1a2588bfc0814ac'],
	output_index => 0,
	output => {
		locking_script => [P2SH => $redeem_script->get_legacy_address],
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
			->push($redeem_script->to_serialized),
		sequence_no => 0xfffffffd,
	);

	$tx->add_output(
		value => 99987088,
		locking_script => [P2SH => '39zAv4u6QBSmUAttAUP6bLvENRMZuNAJaP'],
	);

	is to_format [hex => $tx->get_hash], $expected_txid, 'txid ok';
	lives_ok {
		$tx->verify(block => btc_block->new(height => 602300))
	} 'input verification ok';
};

subtest 'should not verify incorrect multisig transactions (P2SH)' => sub {
	$tx = btc_transaction->new(
		version => 2,
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
			->push($redeem_script->to_serialized),
		sequence_no => 0xfffffffd,
	);

	$tx->add_output(
		value => 99987088,
		locking_script => [P2SH => '39zAv4u6QBSmUAttAUP6bLvENRMZuNAJaP'],
	);

	# NOTE: modified signature - no txid test
	dies_ok { $tx->verify } 'input verification ok';
};

subtest 'should verify multisig transactions (P2WSH)' => sub {
	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'0100000000010170800804cd99ddfd02986237b98510d64f69aa2861ead9374f218a4bdb37dfe40100000000ffffffff02d45202000000000017a9142dc36d24e65d10677d4bc8fb460ce2c53c944beb87effabb080000000022002041e21222becb40dac9bcd3092960116f6ecd1ee19b841db254892b5830acc7a8040047304402204598870f6bdf1658f6cfff05cf6e3df04846290da62dfea8a5403635aa0edcc4022043b0ab93d33cf64fd369857aa0de7836374b4823c11d77cebd43748ddd74b2030147304402207998d8c1be59e1be0ba20f9cfbe954755fbb3de61f39e758054d23e0daca6c3302201bf6f916c969d02396aa082239759baa37c010f9612522503c2960f7dc28306e0147522103e3ab4fee9dd471f66d75d68addcb75ce8e9ba9183c7fc334d8064ae7e87e3b8a2103a3af0f49a21d29106ebeef9b3c3d69fc375c856a7153d97156a5b7a161ca6c2552ae00000000'
		]
	);

	lives_ok { $tx->verify } 'input verification ok';
	lives_ok { $tx->verify } 'input verification ok (second time)';

	# NOTE: try modifying witness signature, see if it still verifies
	# (segwit transactions are backward compatible, so it would pass without support for segwit)
	$tx->inputs->[0]->witness->[1] .= "\x01";
	throws_ok { $tx->verify } 'Bitcoin::Crypto::Exception::Transaction',
		'input verification ok after modifying witness';
};

subtest 'should verify multisig transactions (nested P2WSH)' => sub {
	$tx = btc_transaction->from_serialized(
		[
			hex =>
				'010000000001010878cbc09dbac9f0ac94611baceed740061865b0c2036606c4d11ae7d546934c01000000232200206b51c60589b671b997a276950b725fc2a2bfd8ceb6fdd3f3b14449469e65304b0000000004f049020000000000160014d1b9203d3c5500cf543300124c496b22025a5bb706eb020000000000160014085a6e45f5918eae38c68141b784a0aab4de0c84e6b45a00000000001976a91405eb7a2f755365f0e10516c557b114122a3cc8b788ac5d54a1000000000017a914cfbb5f75ffb798b37e1f4905b65a3c2d160a9b81870400483045022100b1c440fa0c1ccbbee578fc138c421eeb42ce65222370123f469e34b34ad9c0e802200d4a91e7cb5510ddd64b993736dc13b8c7975df0cc32c8d2a41a8c50b290efaa01483045022100db29096065371b9d0de8b6c40b0b4744ed2d38022542d7c27be6ca926907a3450220021ed313618f6a77a872b521f51773cfd0dc815003344b2005da3380b157a6c60147522103d601c46b6f63f6866758d4d32f95ce50fce897e23374c68a37f25888fc3e6a7c21035db528ca03dfb59d6874b0c01077b1116101a4a9a47db365e2002d298aaa373c52ae00000000'
		]
	);

	lives_ok { $tx->verify } 'input verification ok';
	lives_ok { $tx->verify } 'input verification ok (second time)';

	# NOTE: try modifying witness signature, see if it still verifies
	# (segwit transactions are backward compatible, so it would pass without support for segwit)
	$tx->inputs->[0]->witness->[1] .= "\x01";
	throws_ok { $tx->verify } 'Bitcoin::Crypto::Exception::Transaction',
		'input verification ok after modifying witness';
};

done_testing;

