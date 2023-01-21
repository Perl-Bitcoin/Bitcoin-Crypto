use v5.10;
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto::Script;

my @cases = (
	[
		'1add',
		[qw(OP_14 OP_1ADD)],
		["\x0f"],
	],

	[
		'1sub',
		[qw(OP_14 OP_1SUB)],
		["\x0d"],
	],

	[
		'negation, single byte (low)',
		[qw(OP_15 OP_NEGATE)],
		["\x8f"],
	],

	[
		'negation, single byte (high)',
		[qw(ff OP_NEGATE)],
		["\x7f"],
	],

	[
		'negation, two bytes (low)',
		[qw(ff01 OP_NEGATE)],
		["\xff\x81"],
	],

	[
		'negation, two bytes (high)',
		[qw(cccc OP_NEGATE)],
		["\xcc\x4c"],
	],

	[
		'negation, three bytes',
		[qw(ffff00 OP_NEGATE)],
		["\xff\xff\x80"],
	],

	[
		'abs, positive',
		[qw(ff7f OP_ABS)],
		["\xff\x7f"],
	],

	[
		'abs, negative',
		[qw(ffff OP_ABS)],
		["\xff\x7f"],
	],

	[
		'addition, single byte',
		[qw(OP_15 OP_16 OP_ADD)],
		["\x1f"],
	],

	[
		'addition, two bytes',
		[qw(ff01 OP_15 OP_ADD)],
		["\x0e\x02"],
	],

	[
		'subtraction, single byte',
		[qw(OP_10 OP_3 OP_SUB)],
		["\x07"],
	],

	[
		'subtraction, two bytes',
		[qw(2345 OP_7 OP_SUB)],
		["\x1c\x45"],
	],

	[
		'size, two bytes',
		[qw(2345 OP_SIZE)],
		["\x23\x45", "\x02"],
	],

	[
		'min',
		[qw(OP_10 OP_5 OP_MIN)],
		[chr 5],
	],

	[
		'max',
		[qw(OP_10 OP_5 OP_MAX)],
		[chr 10],
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

