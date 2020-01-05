use Modern::Perl "2010";
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto::Exception')};

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
	local $SIG{__WARN__} = sub { die shift . " - warning" };
	throws_ok {
		Bitcoin::Crypto::Exception->warn(code => "test_code", message => "test_message");
	} qr/\(test_code\) - warning/, "warning was raised as exception";
	my $err = $@;

	note("$err");
}

done_testing;

