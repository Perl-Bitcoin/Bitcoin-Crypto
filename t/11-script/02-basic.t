use v5.10;
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto::Script;

subtest 'testing data push' => sub {
	my $data = pack 'H*', '00010203';

	my @cases = (
		$data x 10,
		$data x 50,
		$data x 90
	);

	my @ops = (
		'OP_PUSHDATA1', # NOTE: simple push is implemented using PUSHDATA1
		'OP_PUSHDATA1',
		'OP_PUSHDATA2',
	);

	for my $case_num (0 .. $#cases) {
		my $case = $cases[$case_num];

		my $script = Bitcoin::Crypto::Script->new
			->push($case);

		ops_are($script, [$ops[$case_num]], "ops $case_num ok");
		stack_is($script, [$case], "stack $case_num ok");
	}
};

done_testing;

