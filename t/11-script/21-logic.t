use v5.10;
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto::Script;

subtest 'testing negation of true value' => sub {
	my @ops = (
		'ff0180',
		'OP_NOT',
	);

	my $script = Bitcoin::Crypto::Script->new;
	script_fill($script, @ops);

	ops_are($script, \@ops);
	stack_is($script, ["\x00"]);
};

subtest 'testing negation of false value' => sub {
	my @ops = (
		'000000',
		'OP_NOT',
	);

	my $script = Bitcoin::Crypto::Script->new;
	script_fill($script, @ops);

	ops_are($script, \@ops);
	stack_is($script, ["\x01"]);
};

subtest 'testing negation of false value (with negative 0)' => sub {
	my @ops = (
		'000080',
		'OP_NOT',
	);

	my $script = Bitcoin::Crypto::Script->new;
	script_fill($script, @ops);

	ops_are($script, \@ops);
	stack_is($script, ["\x01"]);
};

done_testing;

