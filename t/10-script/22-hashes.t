use v5.10;
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use ScriptTest;

use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA1 qw(sha1);
use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::Crypto::Util qw(hash160 hash256);
use Bitcoin::Crypto::Script;

my $input = 'test input!';
my $input_hex = unpack 'H*', $input;

my @cases = (
	[
		'ripemd160',
		[$input_hex, 'OP_RIPEMD160'],
		[ripemd160($input)],
	],
	[
		'sha1',
		[$input_hex, 'OP_SHA1'],
		[sha1($input)],
	],
	[
		'sha256',
		[$input_hex, 'OP_SHA256'],
		[sha256($input)],
	],
	[
		'hash160',
		[$input_hex, 'OP_HASH160'],
		[hash160($input)],
	],
	[
		'hash256',
		[$input_hex, 'OP_HASH256'],
		[hash256($input)],
	],
);

foreach my $case (@cases) {
	my ($hash_name, $ops, $expected_stack) = @$case;

	subtest "testing $hash_name" => sub {
		my $script = Bitcoin::Crypto::Script->new;
		script_fill($script, @$ops);

		ops_are($script, $ops);
		stack_is($script, $expected_stack);
	};
}

done_testing;

