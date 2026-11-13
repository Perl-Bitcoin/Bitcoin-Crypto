use Test2::V0;
use Bitcoin::Crypto::Script;

use lib 't/lib';
use ScriptTest;

# four bytes
my $data = pack 'H*', '00010203';

my @cases = (
	[
		'OP_PUSH',
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

subtest 'testing success calls' => sub {
	ok(!Bitcoin::Crypto::Script->new->run->success, 'success with empty script ok');
	ok(!Bitcoin::Crypto::Script->new->add('OP_0')->run->success, 'success with OP_0 ok');
	ok(Bitcoin::Crypto::Script->new->add('OP_1')->run->success, 'success with OP_1 ok');
	ok(Bitcoin::Crypto::Script->new->push('0')->run->success, 'success with pushed 0 ok');
};

done_testing;

