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
		ops => [qw(OP_NOP)],
		stack => [],
	},

	{
		ops => [qw(OP_1 OP_2 OP_2DUP OP_ROT OP_EQUAL OP_TOALTSTACK OP_EQUAL OP_FROMALTSTACK)],
		stack => [chr 1, chr 1],
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

	{
		ops => [qw(OP_1 OP_2 OP_3 OP_4 OP_5 OP_6 OP_2ROT OP_2 OP_ROLL OP_3DUP OP_2OVER OP_2SWAP)],
		stack => [chr 3, chr 4, chr 5, chr 1, chr 2, chr 6, chr 1, chr 6, chr 1, chr 2, chr 6],
	},

	{
		ops => [qw(OP_5 OP_5 OP_2DROP OP_1 OP_2 OP_TUCK OP_1 OP_PICK)],
		stack => [chr 2, chr 1, chr 2, chr 1],
	},

	{
		ops => [qw(OP_10 OP_11 OP_12 OP_OVER OP_NIP OP_DEPTH OP_IFDUP OP_0 OP_IFDUP)],
		stack => [chr 10, chr 11, chr 11, chr 3, chr 3, chr 0],
	},

	{
		ops => [qw(OP_1 OP_IF dead OP_ELSE beef OP_ENDIF)],
		stack => ["\xde\xad"],
	},

	{
		ops => [qw(OP_0 OP_IF dead OP_ELSE beef OP_ENDIF)],
		stack => ["\xbe\xef"],
	},

	{
		ops => [qw(OP_0 OP_NOTIF dead OP_ELSE beef OP_ENDIF)],
		stack => ["\xde\xad"],
	},

	{
		ops => [qw(f8 f8 OP_SUB OP_0 OP_EQUAL)],
		stack => ["\x01"],
	},

	{
		ops => [qw(f8 f8 OP_NEGATE OP_ADD OP_0 OP_EQUAL)],
		stack => ["\x01"],
	},

	{
		ops => [qw(
			OP_1 OP_1
			OP_IF
				OP_IF
					dead
				OP_ELSE
					face
				OP_ENDIF
			OP_ELSE
				OP_IF
					beef
				OP_ELSE
					feed
				OP_ENDIF
			OP_ENDIF
		)],
		stack => ["\xde\xad"],
	},

	{
		ops => [qw(
			OP_0 OP_1
			OP_IF
				OP_IF
					dead
				OP_ELSE
					face
				OP_ENDIF
			OP_ELSE
				OP_IF
					beef
				OP_ELSE
					feed
				OP_ENDIF
			OP_ENDIF
		)],
		stack => ["\xfa\xce"],
	},

	{
		ops => [qw(
			OP_1 OP_0
			OP_IF
				OP_IF
					dead
				OP_ELSE
					face
				OP_ENDIF
			OP_ELSE
				OP_IF
					beef
				OP_ELSE
					feed
				OP_ENDIF
			OP_ENDIF
		)],
		stack => ["\xbe\xef"],
	},

	{
		ops => [qw(
			OP_0 OP_0
			OP_IF
				OP_IF
					dead
				OP_ELSE
					face
				OP_ENDIF
			OP_ELSE
				OP_IF
					beef
				OP_ELSE
					feed
				OP_ENDIF
			OP_ENDIF
		)],
		stack => ["\xfe\xed"],
	},
);

my $case_num = 0;
foreach my $case (@cases) {
	subtest "testing script execution for case $case_num" => sub {
		my @ops = @{$case->{ops}};

		my $script = Bitcoin::Crypto::Script->new;
		script_fill($script, @ops);

		ops_are($script, \@ops, "ops ok");

		try {
			stack_is($script, $case->{stack}, "stack ok");
		}
		catch {
			if ($case->{exception}) {
				isa_ok $_, 'Bitcoin::Crypto::Exception::ScriptRuntime';
			}
			else {
				fail "got exception: $_";
			}
		};
	};

	++$case_num;
};

done_testing;

