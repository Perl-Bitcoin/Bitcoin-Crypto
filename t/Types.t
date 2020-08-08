use v5.10; use warnings;
use Test::More;
use Test::Exception;
use Bitcoin::Crypto;

BEGIN { use_ok('Bitcoin::Crypto::Types', qw(:all)) };

is(Bitcoin::Crypto::Types->VERSION, Bitcoin::Crypto->VERSION);

{
	package TestMoo;
	use Moo;
	use Bitcoin::Crypto::Types -types;

	has "t1" => (
		is => "ro",
		isa => IntMaxBits[5],
		coerce => 1,
	);

	has "t3" => (
		is => "ro",
		isa => IntMaxBits[128],
		coerce => 1,
	);
}

my %data = (
	invalid => [
		{t1 => 32},
		{t1 => 33},
		{t1 => -1},
		{t3 => do { use bigint; 2 << 127 }},
		{t3 => -1},
	],
	valid => [
		{t1 => 0},
		{t1 => 10},
		{t1 => 31},
		{t3 => do { use bigint; 2 << 70 }},
		{t3 => do { use bigint; (2 << 127) - 1 }},
		{t3 => 0},
	]
);

foreach my $case (@{$data{invalid}}) {
	dies_ok {
		TestMoo->new(%$case);
	} "types fail for invalid data";
}

foreach my $case (@{$data{valid}}) {
	lives_ok {
		TestMoo->new(%$case);
	} "types pass for valid data";
}

done_testing;
