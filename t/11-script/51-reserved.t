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
		ops => [qw(OP_RESERVED)],
		exception => 1,
	},

	{
		ops => [qw(OP_RESERVED1)],
		exception => 1,
	},

	{
		ops => [qw(OP_RESERVED2)],
		exception => 1,
	},

	{
		ops => [qw(OP_VER)],
		exception => 1,
	},

	{
		ops => [qw(OP_VERIF)],
		exception => 1,
	},

	{
		ops => [qw(OP_VERNOTIF)],
		exception => 1,
	},

	{
		ops => [qw(OP_NOP1)],
	},

	{
		ops => [qw(OP_NOP4)],
	},

	{
		ops => [qw(OP_NOP5)],
	},

	{
		ops => [qw(OP_NOP6)],
	},

	{
		ops => [qw(OP_NOP7)],
	},

	{
		ops => [qw(OP_NOP8)],
	},

	{
		ops => [qw(OP_NOP9)],
	},

	{
		ops => [qw(OP_NOP10)],
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
			$script->run;
			fail "No exception!" if $case->{exception};
		}
		catch {
			if ($case->{exception}) {
				isa_ok $_, 'Bitcoin::Crypto::Exception::TransactionScript';
			}
			else {
				fail "got exception: $_";
			}
		};
	};

	++$case_num;
}

done_testing;

