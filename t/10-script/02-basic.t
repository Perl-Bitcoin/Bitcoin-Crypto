use v5.10;
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use ScriptTest;

use Bitcoin::Crypto::Script;

# four bytes
my $data = pack 'H*', '00010203';

my @cases = (
	[
		'OP_PUSHDATA1',
		$data x 10,
	],
	[
		'OP_PUSHDATA1',
		$data x 50,
	],
	[
		'OP_PUSHDATA2',
		$data x 90,
	],
);

foreach my $case (@cases) {
	my ($op, $data) = @{$case};

	subtest "testing $op" => sub {
		my $script = Bitcoin::Crypto::Script->new
			->push($data);

		ops_are($script, [$op], "ops ok");
		stack_is($script, [$data], "stack ok");
	};
}

subtest 'testing OP_1NEGATE' => sub {
	my $script = Bitcoin::Crypto::Script->new
		->add('OP_1NEGATE');

	ops_are($script, ['OP_1NEGATE'], "ops ok");
	stack_is($script, [chr 0x81], "stack ok");
};

done_testing;

