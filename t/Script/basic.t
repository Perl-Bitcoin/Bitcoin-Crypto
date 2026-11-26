use Test2::V0;
use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Util qw(to_format);

use lib 't/lib';
use ScriptTest;

# four bytes
my $data = pack 'H*', '00010203';

my @cases = (
	[
		'OP_PUSH',
		$data x 10,
		'364aaf690a8ba482ea5be471621ef237aad5ee9b',
		'ee5c70047c253cd90a7223be3e29c6ef28312a644a00fbb1579b03ef199a9720',
	],
	[
		'OP_PUSHDATA1',
		$data x 50,
		'85a61d0f94c0102bc1800ab5d1984c861568562a',
		'f0e028ddc4ebc2a06096e6052f79b4786dd73453084e46d4fef1bb5622ce9868',
	],
	[
		'OP_PUSHDATA2',
		$data x 90,
		'693f01ad2bc7a23442fa5e33dbb5eae1bff0f592',
		'cee716eb896065a10f0a94a8e030491ceb1191eb915cf5b081b123ed2790259b',
	],
);

foreach my $case (@cases) {
	my ($op, $data, $hash, $witness_hash) = @{$case};

	subtest "testing $op" => sub {
		my $script = Bitcoin::Crypto::Script->new
			->push($data);

		ops_are($script, [$op], "ops ok");
		stack_is($script, [$data], "stack ok");

		is to_format [hex => $script->get_hash], $hash, 'get_hash ok';
		is to_format [hex => $script->get_witness_hash], $witness_hash, 'get_witness_hash ok';
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

