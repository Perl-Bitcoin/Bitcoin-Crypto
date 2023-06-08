use v5.10;
use strict;
use warnings;
use Test::More;
use Try::Tiny;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto qw(btc_transaction);
use Bitcoin::Crypto::Script;

my @cases = (
	[
		'locktime - no transaction',
		undef,
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		'Bitcoin::Crypto::Exception::Transaction',
	],
	[
		'locktime - zero',
		{locktime => 0},
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		'Bitcoin::Crypto::Exception::ScriptInvalid',
	],
	[
		'locktime - satisfied',
		{locktime => 21333},
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		undef,
	],
	[
		'locktime - unsatisfied',
		{locktime => 21332},
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		'Bitcoin::Crypto::Exception::ScriptInvalid',
	],
);

foreach my $case (@cases) {
	my ($hash_name, $args, $ops, $expected_stack, $exception) = @$case;

	subtest "testing $hash_name" => sub {
		my $script = Bitcoin::Crypto::Script->new;
		my $alive = 1;

		script_fill($script, @$ops);
		ops_are($script, $ops);

		try {
			stack_is(sub { $script->run($args ? (transaction => btc_transaction->new($args)) : ()) }, $expected_stack);
			fail "should've died" if $exception;
		}
		catch {
			my $ex = $_;

			if ($exception) {
				isa_ok $ex, $exception;
			}
			else {
				note "died: $ex";
				fail "should've lived";
			}
		};
	};
}

done_testing;

