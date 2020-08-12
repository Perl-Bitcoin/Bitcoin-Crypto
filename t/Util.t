use v5.10; use warnings;
use Test::More;
use Test::Exception;
use Math::BigInt;
use Bitcoin::Crypto;

BEGIN { use_ok('Bitcoin::Crypto::Util', qw(validate_wif get_path_info)) }

is(Bitcoin::Crypto::Util->VERSION, Bitcoin::Crypto->VERSION);

# validate_wif - 3 tests

my %cases = (
	"935hpxoy4BGeuHmmtjURq52SehWtRoSArv6mJVZbVXUWyN9HQ5T" => !!1,
	"Aammc6SScZZF47CuWe4Wn91kDE" => !!0,
	"IOU" => undef,
);

foreach my $case (keys %cases) {
	if (defined $cases{$case}) {
		lives_and {
			is(validate_wif($case), $cases{$case})
		}
		"wif validation ok";
	}
	else {
		throws_ok {
			validate_wif($case);
		}
		"Bitcoin::Crypto::Exception", "wif validation failed as expected";
	}
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

done_testing;
