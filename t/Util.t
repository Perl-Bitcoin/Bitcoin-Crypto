use strict;
use warnings;

use Test::More tests => 13;
use Math::BigInt;
use Try::Tiny;

BEGIN { use_ok('Bitcoin::Crypto::Util', qw(validate_wif validate_address get_path_info)) };

# validate_wif - 3 tests

my %cases = (
	"935hpxoy4BGeuHmmtjURq52SehWtRoSArv6mJVZbVXUWyN9HQ5T" => !!1,
	"Aammc6SScZZF47CuWe4Wn91kDE" => !!0,
	"IOU" => undef,
);

foreach my $case (keys %cases) {
	try {
		my $is_valid = validate_wif($case);
		if (defined $cases{$case}) {
			is($is_valid, $cases{$case}, "wif validation ok");
		} else {
			fail("wif validation should've failed but didn't");
		}
	} catch {
		if (defined $cases{$case}) {
			fail("wif validation should've passed but didn't");
		} else {
			pass("wif validation failed as expected");
		}
	};
}


# validate_address - 3 tests

%cases = (
	"mpyspBXHGvDMGiV6RpeWeVvSierBhysfdq" => !!1,
	"Aammc6SScZZF47CuWe4Wn91kDE" => !!0,
	"IOU" => undef,
);

foreach my $case (keys %cases) {
	try {
		my $is_valid = validate_address($case);
		if (defined $cases{$case}) {
			is($is_valid, $cases{$case}, "address validation ok");
		} else {
			fail("address validation should've failed but didn't");
		}
	} catch {
		if (defined $cases{$case}) {
			fail("address validation should've passed but didn't");
		} else {
			pass("address validation failed as expected");
		}
	};
}

my @path_test_data = (
	[
		"m/0'/1/2/3'",
		{
			private => !!1,
			path => [
				2 << 30,
				1,
				2,
				3 + (2 << 30)
			]
		}
	],
	[
		"M/31311'/2/3",
		{
			private => !!0,
			path => [
				31311 + (2 << 30),
				2,
				3
			],
		},
	],
	[
		"m/0'/-1",
		undef
	],
	[
		"M/m/1111",
		undef
	],
	[
		"m/4500000000/1",
		undef
	],
	[
		"M/1/2/4500000000'",
		undef
	],
);


for my $case (@path_test_data) {
	is_deeply(get_path_info($case->[0]), $case->[1], "test case $case->[0]");
}
