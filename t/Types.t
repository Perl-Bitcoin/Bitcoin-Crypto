use strict;
use warnings;

use Test::More;
use Try::Tiny;

BEGIN { use_ok('Bitcoin::Crypto::Types', qw(:all)) };

package TestMoo {
	use Moo;
	use Bitcoin::Crypto::Types qw(:all);

	has "t1" => (
		is => "ro",
		isa => IntMaxBits[5]
	);

	has "t2" => (
		is => "ro",
		isa => StrExactLength[2]
	);
}

my %data = (
	invalid => [
		{t1 => 32},
		{t1 => 33},
		{t1 => -1},
		{t2 => "a"},
		{t2 => "abc"},
	],
	valid => [
		{t1 => 0},
		{t1 => 10},
		{t1 => 31},
		{t2 => "ao"},
	]
);

foreach my $case (@{$data{invalid}}) {
	try {
		TestMoo->new(%$case);
		fail("types pass for invalid data");
	} catch {
		pass("types fail for invalid data");
	};
}

try {
	foreach my $case (@{$data{valid}}) {
		TestMoo->new(%$case);
	}
	pass("types pass for valid data");
} catch {
	fail("types fail for valid data");
};

done_testing;
