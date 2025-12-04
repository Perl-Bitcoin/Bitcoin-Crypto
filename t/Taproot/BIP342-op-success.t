use Test2::V0;
use Bitcoin::Crypto qw(btc_tapscript);
use Bitcoin::Crypto::Script::Runner;

my @cases = (80, 98, 126 .. 129, 131 .. 134, 137, 138, 141, 142, 149 .. 153, 187 .. 254);

foreach my $succ (@cases) {
	subtest "should correctly handle success code $succ" => sub {

		# script is weak_ref - need to make a var
		my $script = btc_tapscript->new->add("OP_SUCCESS$succ")->add('OP_VERIF');
		my $compiler = Bitcoin::Crypto::Script::Compiler->compile($script);

		ok $compiler->unconditionally_valid, 'script is unconditionally_valid ok';
		ok $script->run->success, 'script success ok';
	};
}

done_testing;

