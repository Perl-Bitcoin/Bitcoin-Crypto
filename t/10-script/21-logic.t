use Test2::V0;
use Bitcoin::Crypto::Script;

use lib 't/lib';
use ScriptTest;

my @cases = (
	[
		'negation of true value',
		[qw(ff0180 OP_NOT)],
		[chr 0],
	],

	[
		'negation of true value (only true LSBit)',
		[qw(010000 OP_NOT)],
		[chr 0],
	],

	[
		'negation of true value (only true MSByte)',
		[qw(000001 OP_NOT)],
		[chr 0],
	],

	[
		'negation of false value',
		[qw(000000 OP_NOT)],
		[chr 1],
	],

	[
		'negation of false value (with negative 0)',
		[qw(000080 OP_NOT)],
		[chr 1],
	],

	[
		'booland 1 0',
		[qw(OP_1 OP_0 OP_BOOLAND)],
		[chr 0],
	],

	[
		'booland 1 1',
		[qw(OP_1 OP_1 OP_BOOLAND)],
		[chr 1],
	],

	[
		'booland 0 1',
		[qw(OP_0 OP_1 OP_BOOLAND)],
		[chr 0],
	],

	[
		'booland 0 0',
		[qw(OP_0 80 OP_BOOLAND)],
		[chr 0],
	],

	[
		'boolor 1 0',
		[qw(OP_1 OP_0 OP_BOOLOR)],
		[chr 1],
	],

	[
		'boolor 1 1',
		[qw(OP_1 OP_1 OP_BOOLOR)],
		[chr 1],
	],

	[
		'boolor 0 1',
		[qw(OP_0 OP_1 OP_BOOLOR)],
		[chr 1],
	],

	[
		'boolor 0 0',
		[qw(OP_0 80 OP_BOOLOR)],
		[chr 0],
	],

	[
		'equal',
		[qw(OP_0 OP_0 OP_EQUAL 22 22 OP_EQUAL OP_0 80 OP_EQUAL OP_0 OP_1 OP_EQUAL)],
		[chr 1, chr 1, chr 0, chr 0],
	],

	[
		'numequal',
		[qw(OP_0 OP_0 OP_NUMEQUAL 22 22 OP_NUMEQUAL OP_0 80 OP_NUMEQUAL OP_0 OP_1 OP_NUMEQUAL)],
		[chr 1, chr 1, chr 1, chr 0],
	],

	[
		'numnotequal',
		[qw(OP_0 OP_0 OP_NUMNOTEQUAL 22 22 OP_NUMNOTEQUAL OP_0 80 OP_NUMNOTEQUAL OP_0 OP_1 OP_NUMNOTEQUAL)],
		[chr 0, chr 0, chr 0, chr 1],
	],

	[
		'0notequal',
		[qw(OP_0 OP_0NOTEQUAL OP_1 OP_0NOTEQUAL)],
		[chr 0, chr 1],
	],

	[
		'lessthan',
		[qw(OP_5 OP_2 OP_LESSTHAN OP_3 OP_3 OP_LESSTHAN OP_4 OP_6 OP_LESSTHAN)],
		[chr 0, chr 0, chr 1],
	],

	[
		'lessthanorequal',
		[qw(OP_5 OP_2 OP_LESSTHANOREQUAL OP_3 OP_3 OP_LESSTHANOREQUAL OP_4 OP_6 OP_LESSTHANOREQUAL)],
		[chr 0, chr 1, chr 1],
	],

	[
		'greaterthan',
		[qw(OP_5 OP_2 OP_GREATERTHAN OP_3 OP_3 OP_GREATERTHAN OP_4 OP_6 OP_GREATERTHAN)],
		[chr 1, chr 0, chr 0],
	],

	[
		'greaterthanorequal',
		[qw(OP_5 OP_2 OP_GREATERTHANOREQUAL OP_3 OP_3 OP_GREATERTHANOREQUAL OP_4 OP_6 OP_GREATERTHANOREQUAL)],
		[chr 1, chr 1, chr 0],
	],

	[
		'within',
		[qw(OP_2 OP_1 OP_5 OP_WITHIN OP_2 OP_2 OP_5 OP_WITHIN OP_5 OP_2 OP_5 OP_WITHIN OP_0 OP_2 OP_5 OP_WITHIN)],
		[chr 1, chr 1, chr 0, chr 0],
	],

);

foreach my $case (@cases) {
	my ($name, $ops, $expected_stack) = @$case;

	subtest "testing $name" => sub {
		my $script = Bitcoin::Crypto::Script->new;
		script_fill($script, @$ops);

		ops_are($script, $ops);
		stack_is($script, $expected_stack);
	};
}

done_testing;

