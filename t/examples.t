use v5.10; use warnings;
use Test::More;
use Test::Exception;
use File::Basename;

my $examples_path = dirname(dirname(__FILE__)) . "/examples";

local $SIG{__WARN__} = sub { };
for my $example (glob "$examples_path/*") {

	# examples should provide their own execution with test cases
	subtest "testing $example" => sub {
		lives_and {
			do $example;
		};
	};
}

done_testing;
