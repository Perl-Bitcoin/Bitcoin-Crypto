use v5.10;
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto::Script;

subtest 'testing negation of true value' => sub {
	my @ops = (
		'OP_NOT',
	);

	my $script = Bitcoin::Crypto::Script->new;
	$script->push("\xff\x01\x80");
	$script->add($_) for @ops;

	ops_are($script, ['OP_PUSHDATA1', @ops]);
	stack_is($script, ["\x00"]);
};

subtest 'testing negation of false value' => sub {
	my @ops = (
		'OP_NOT',
	);

	my $script = Bitcoin::Crypto::Script->new;
	$script->push("\x00\x00\x00");
	$script->add($_) for @ops;

	ops_are($script, ['OP_PUSHDATA1', @ops]);
	stack_is($script, ["\x01"]);
};

subtest 'testing negation of false value (with negative 0)' => sub {
	my @ops = (
		'OP_NOT',
	);

	my $script = Bitcoin::Crypto::Script->new;
	$script->push("\x00\x00\x80");
	$script->add($_) for @ops;

	ops_are($script, ['OP_PUSHDATA1', @ops]);
	stack_is($script, ["\x01"]);
};

done_testing;

