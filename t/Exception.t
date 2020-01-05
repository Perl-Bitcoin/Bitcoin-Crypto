use Modern::Perl "2010";
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto::Exception')};

{
	throws_ok {
		Bitcoin::Crypto::Exception->raise("test_message");
	} "Bitcoin::Crypto::Exception", "exception was raised";
	throws_ok {
		Bitcoin::Crypto::Exception->throw("test_message");
	} "Bitcoin::Crypto::Exception", "exception was raised";
	my $err = $@;

	is($err->message, "test_message", "message ok");
	ok("$err" =~ /test_message/, "class stringified");
	note("$err");
}

{
	throws_ok {
		Bitcoin::Crypto::Exception::KeyCreate->raise("message");
	} "Bitcoin::Crypto::Exception::KeyCreate", "exception was raised";

	note("$@");
}

done_testing;

