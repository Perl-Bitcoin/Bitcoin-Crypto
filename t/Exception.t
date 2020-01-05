use Modern::Perl "2010";
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto::Exception')};

local $SIG{__WARN__} = sub { die shift };

{
	throws_ok {
		Bitcoin::Crypto::Exception->raise(code => "test_code", message => "test_message");
	} "Bitcoin::Crypto::Exception", "exception was raised";
	my $err = $@;

	ok($err->is_exception, "it's an exception");
	is($err->code, "test_code", "code ok");
	is($err->message, "test_message", "message ok");
	ok("$err" =~ /test_message/, "class stringified");
	note("$err");
}

{
	dies_ok {
		Bitcoin::Crypto::Exception->raise();
	} "error was raised";

	note("$@");
}

{
	throws_ok {
		Bitcoin::Crypto::Exception->warn(code => "test_code", message => "test_message");
	} "Bitcoin::Crypto::Exception", "exception was raised";
	my $err = $@;

	ok(!$err->is_exception, "it's a warning");
	note("$err");
}

done_testing;

