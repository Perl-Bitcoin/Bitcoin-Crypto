use Test2::V0;
use Bitcoin::Crypto qw(btc_tapscript);
use Bitcoin::Crypto::Script::Runner;

my @cases = (80, 98, 126 .. 129, 131 .. 134, 137, 138, 141, 142, 149 .. 153, 187 .. 254);

my $runner = Bitcoin::Crypto::Script::Runner->new;
foreach my $succ (@cases) {
	subtest "should correctly handle success code $succ" => sub {
		$runner->set_script(btc_tapscript->new->add("OP_SUCCESS$succ"));
		my $ex = dies {
			$runner->compile;
		};

		isa_ok $ex, 'Bitcoin::Crypto::Exception::ScriptSuccess';

		$runner->execute($runner->script);
		ok $runner->success, 'script success ok';
	};
}

done_testing;

