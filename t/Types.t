use Modern::Perl "2010";
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto::Types', qw(:all)) };

{
	package TestMoo;
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

	has "t3" => (
		is => "ro",
		isa => IntMaxBits[128]
	);
}

my %data = (
	invalid => [
		{t1 => 32},
		{t1 => 33},
		{t1 => -1},
		{t2 => "a"},
		{t2 => "abc"},
		{t2 => "aś"},
		{t3 => do { use bigint; 2 << 127 }},
		{t3 => -1},
	],
	valid => [
		{t1 => 0},
		{t1 => 10},
		{t1 => 31},
		{t2 => "ao"},
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
