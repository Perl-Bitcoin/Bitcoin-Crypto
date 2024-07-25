use Test2::V0;
use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Script::Runner;

use lib 't/lib';
use ScriptTest;

my @cases = (
	{
		ops => [
			qw(
				OP_2
				OP_0
				OP_IFDUP
				OP_TOALTSTACK
				OP_DUP
				OP_2DROP
			)
		],
		steps => [
			[chr 2],
			[chr 2, ''],
			[chr 2, ''],
			[chr 2],
			[chr 2, chr 2],
			[],
		],
	},

	{
		ops => [
			qw(
				OP_10
				OP_2
				OP_ADD
				OP_12
				OP_EQUAL
				OP_IF
				dead
				OP_ELSE
				beef
				OP_ENDIF
			)
		],
		steps => [
			[chr 10],
			[chr 10, chr 2],
			[chr 12],
			[chr 12, chr 12],
			[chr 1],
			[],    # OP_IF
			["\xde\xad"],
			["\xde\xad"],    # OP_ELSE
							 # no OP_ENDIF, since we jumped past it
		],
	},
);

my $case_num = 0;
for my $case (@cases) {
	subtest "testing scripts step by step case $case_num" => sub {
		my @ops = @{$case->{ops}};
		my @steps = @{$case->{steps}};

		my $script = Bitcoin::Crypto::Script->new;
		script_fill($script, @ops);

		ops_are($script, \@ops, "ops ok");

		my $runner = Bitcoin::Crypto::Script::Runner->new;
		$runner->start($script);

		my $step_no = 0;
		while ($runner->step) {
			stack_is($runner, shift @steps, "stack step $step_no ok");
			++$step_no;
		}

		ok !@steps, 'number of steps ok';
	};

	++$case_num;
}

done_testing;

