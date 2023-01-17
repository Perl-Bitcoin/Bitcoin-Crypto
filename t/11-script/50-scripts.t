use v5.10;
use strict;
use warnings;
use Test::More;
use Try::Tiny;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto::Script;

my @cases = (
	{
		ops => [qw(OP_1 OP_2 OP_2DUP OP_ROT OP_EQUAL OP_TOALTSTACK OP_EQUAL OP_FROMALTSTACK)],
		stack => ["\x01", "\x01"],
	},

	{
		ops => [qw(0102 0102 OP_EQUALVERIFY ffFF)],
		stack => ["\xff\xff"],
	},

	{
		ops => [qw(0102 0202 OP_EQUALVERIFY)],
		exception => 1,
	},

	{
		ops => [qw(OP_RETURN OP_3 OP_4 OP_5 OP_6 OP_7 OP_8 OP_9 OP_10 OP_11 OP_12 OP_13 OP_14 OP_15 OP_16)],
		exception => 1,
	},
);

foreach my $case_num (0 .. $#cases) {
	my $case = $cases[$case_num];
	my @ops = @{$case->{ops}};

	my $script = Bitcoin::Crypto::Script->new;
	foreach my $op (@ops) {
		if ($op =~ m/^OP_/) {
			$script->add($op);
		}
		else {
			$script->push(pack 'H*', $op);
			$op = 'OP_PUSHDATA1';
		}
	}

	ops_are($script, \@ops, "case $case_num ops ok");

	try {
		stack_is($script, $case->{stack}, "case $case_num stack ok");
	}
	catch {
		if ($case->{exception}) {
			isa_ok $_, 'Bitcoin::Crypto::Exception::ScriptRuntime';
		}
		else {
			fail "case $case_num got exception: $_";
		}
	};
};

done_testing;

