use Test2::V0;
use Bitcoin::Crypto qw(btc_script btc_tapscript);
use Bitcoin::Crypto::Script::Runner;

my $runner = Bitcoin::Crypto::Script::Runner->new;

subtest 'should allow non-minimal bools in script ifs' => sub {
	ok lives {
		$runner->execute(
			btc_script->new
				->add('OP_5')
				->add('OP_IF')
				->add('OP_1')
				->add('OP_ENDIF')
		);
	}, 'no exception ok';

	ok $runner->success, 'script success ok';
};

subtest 'should require minimal bools in tapscript ifs' => sub {
	my $ex = dies {
		$runner->execute(
			btc_tapscript->new
				->add('OP_5')
				->add('OP_IF')
				->add('OP_1')
				->add('OP_ENDIF')
		);
	};

	isa_ok $ex, 'Bitcoin::Crypto::Exception::TransactionScript';

	ok lives {
		$runner->execute(
			btc_tapscript->new
				->add('OP_1')
				->add('OP_IF')
				->add('OP_1')
				->add('OP_ENDIF')
		);
	}, 'no exception ok';
};

done_testing;

