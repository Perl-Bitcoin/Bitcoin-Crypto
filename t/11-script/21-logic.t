use v5.10;
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto::Script;

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
		[qw(OP_0 OP_0 OP_EQUAL 22 22 OP_EQUAL OP_0 80 OP_EQUAL)],
		[chr 1, chr 1, chr 0],
	],

	[
		'numequal',
		[qw(OP_0 OP_0 OP_NUMEQUAL 22 22 OP_NUMEQUAL OP_0 80 OP_NUMEQUAL)],
		[chr 1, chr 1, chr 1],
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

