use v5.10;
use strict;
use warnings;
use Test::More;
use Try::Tiny;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto qw(btc_transaction);
use Bitcoin::Crypto::Script;

my $input = 'test input!';
my $input_hex = unpack 'H*', $input;

my @cases = (
	[
		'locktime - no transaction',
		undef,
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		0,
	],
	[
		'locktime - zero',
		{locktime => 0},
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		0,
	],
	[
		'locktime - satisfied',
		{locktime => 21333},
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		1,
	],
	[
		'locktime - unsatisfied',
		{locktime => 21332},
		['5553', 'OP_CHECKLOCKTIMEVERFIY'],
		[],
		0,
	],
);

foreach my $case (@cases) {
	my ($hash_name, $args, $ops, $expected_stack, $lives) = @$case;
	$lives //= 1;
	$args //= {};

	subtest "testing $hash_name" => sub {
		my $script = Bitcoin::Crypto::Script->new;
		my $alive = 1;

		script_fill($script, @$ops);
		ops_are($script, $ops);

		try {
			stack_is(sub { $script->run(transaction => btc_transaction->new($args)) }, $expected_stack);
		}
		catch {
			note "died: $_";
			$alive = 0;
		};

		ok !!$lives eq !!$alive, "should've " . ($lives ? 'lived' : 'died');
	};
}

done_testing;

