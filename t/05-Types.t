use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto::Types', qw(-types)) }

use Bitcoin::Crypto::Constants;

subtest 'testing IntMaxBits[5]' => sub {
	my $type = IntMaxBits [5];

	foreach my $valid (qw(0 10 31)) {
		ok $type->check($valid), 'valid check ok';
	}

	foreach my $invalid (qw(32 33 -1)) {
		ok !$type->check($invalid), 'invalid check ok';
	}
};

subtest 'testing IntMaxBits[31]' => sub {
	my $type = IntMaxBits [31];

	foreach my $valid ((1 << 31) - 1) {
		ok $type->check($valid), 'valid check ok';
	}

	foreach my $invalid (1 << 31) {
		ok !$type->check($invalid), 'invalid check ok';
	}
};

subtest 'testing IntMaxBits[60]' => sub {
	plan skip_all => 'requires 64 bit system'
		unless Bitcoin::Crypto::Constants::is_64bit;

	my $type = IntMaxBits [60];

	foreach my $valid ((1 << 60) - 1) {
		ok $type->check($valid), 'valid check ok';
	}

	foreach my $invalid (1 << 60) {
		ok !$type->check($invalid), 'invalid check ok';
	}
};

subtest 'testing BIP44Purpose' => sub {
	my $type = BIP44Purpose;

	for my $valid (undef, qw(44 49 84)) {
		ok $type->check($valid), 'valid check ok';
	}

	for my $invalid (qw(43 144)) {
		ok !$type->check($invalid), 'invalid check ok';
	}
};

subtest 'testing ByteStr' => sub {
	my $type = ByteStr;

	ok $type->check(join '', map chr, 0 .. 255), 'byte range ok';
	ok $type->check(''), 'empty string ok';
	ok !$type->check(chr(255) . chr(256)), 'non-byte string check ok';
	ok !$type->check(undef), 'undef check ok';
};

done_testing;

