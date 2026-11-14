use Test2::V0;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Constants qw(:script);

subtest 'should detect P2PKH / P2SH mismatch' => sub {
	isa_ok dies {
		btc_script->from_standard(P2PKH => '3HDtyBHZ4111BFtUBY2SA4eXJQxifmaTYw');
	}, 'Bitcoin::Crypto::Exception::NetworkCheck';

	isa_ok dies {
		btc_script->from_standard(P2SH => '1AshirGYwnrFsN82DpV83NDfQpRJMuXxLQ');
	}, 'Bitcoin::Crypto::Exception::NetworkCheck';
};

subtest 'should detect P2WPKH / P2WSH mismatch' => sub {
	isa_ok dies {
		btc_script->from_standard(P2WPKH => 'bc1qxrv57xwn050dht30kt9msenkqf67rh0cjcurhukznucjwk63xm3skajjcc');
	}, 'Bitcoin::Crypto::Exception::SegwitProgram';

	isa_ok dies {
		btc_script->from_standard(P2WSH => 'bc1q73vqlq8ptpjhd4pnghqq0gvn3nqh4tn00utypf');
	}, 'Bitcoin::Crypto::Exception::SegwitProgram';
};

subtest 'should detect P2WPKH from different network' => sub {
	isa_ok dies {
		btc_script->from_standard(P2WPKH => 'tb1q26jy9d4vkfqezh6hm7qp7txvk8nggkwv2y72x0');
	}, 'Bitcoin::Crypto::Exception::NetworkCheck';
};

subtest 'should not mistake P2WSH for P2TR' => sub {
	isa_ok dies {
		btc_script->from_standard(P2TR => 'bc1qxrv57xwn050dht30kt9msenkqf67rh0cjcurhukznucjwk63xm3skajjcc');
	}, 'Bitcoin::Crypto::Exception::SegwitProgram';
};

subtest 'should allow creating a P2MS standard script with exotic configuration' => sub {
	ok lives {
		btc_script->from_standard(
			P2MS => [0],
		);
	}, 'empty P2MS';

	ok lives {
		btc_script->from_standard(
			P2MS => [
				0,
				("02" . "01" x 32) x 20,
			],
		);
	}, 'zero signatures and max public keys';
};

subtest 'should disallow creating a P2MS standard script with incorrect configuration' => sub {
	ok dies {
		btc_script->from_standard(
			P2MS => [
				-1,
				"02" . "01" x 32,
			]
		);
	}, 'negative number of signatures';

	ok dies {
		btc_script->from_standard(
			P2MS => [
				1,
			]
		);
	}, 'more signatures than public keys';

	ok dies {
		btc_script->from_standard(
			P2MS => [
				21,
				("02" . "01" x 32) x 21,
			]
		);
	}, 'too many public keys';
};

# NOTE: not checking regular pushdata here or OP_N, as they are all run by the same handler
subtest 'should check stack size after opcodes adding stack elements' => sub {
	my @ops = qw(OP_2DUP OP_3DUP OP_2OVER OP_IFDUP OP_DEPTH OP_DUP OP_OVER OP_PICK OP_TUCK OP_SIZE);

	foreach my $op (@ops) {
		my $script = btc_script->new;

		# NOTE: initial stack size is actually only checked in tapscript. Set
		# this to max + 1, which allows us to test OP_PICK (which only adds an
		# element after removing one)
		ok dies { $script->run(("\x01") x (SCRIPT_MAX_STACK_ELEMENTS + 1)) }, "stack size checked ok for $op";
	}
};

subtest 'should allow creation of NULLDATA with content 0' => sub {
	ok lives {
		btc_script->from_standard(NULLDATA => 0);
	}, 'script creation ok';
};

subtest 'minimal data should correctly handle negative numbers' => sub {
	my $script = btc_script->new->add('OP_1NEGATE')->add('OP_1ADD');
	my $runner = Bitcoin::Crypto::Script::Runner->new(flags => {minimal_data => !!1});

	ok lives { $runner->execute($script) }, 'negative numbers execute ok';
	is $runner->to_int($runner->stack->[-1]), 0, 'negative numbers handled correctly ok';
};

done_testing;

