use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto::Exception') }

{
	throws_ok {
		Bitcoin::Crypto::Exception->raise("test_message");
	}
	"Bitcoin::Crypto::Exception", "exception was raised";
	throws_ok {
		Bitcoin::Crypto::Exception->throw("test_message");
	}
	"Bitcoin::Crypto::Exception", "exception was raised";
	my $err = $@;

	is($err->message, "test_message", "message ok");
	ok("$err" =~ /test_message/, "class stringified");
	note("$err");
}

{
	throws_ok {
		Bitcoin::Crypto::Exception::KeyCreate->raise("message");
	}
	"Bitcoin::Crypto::Exception::KeyCreate", "exception was raised";

	note $@;
}

{

	package BuggyDestroy;

	sub new
	{
		return bless {}, __PACKAGE__;
	}

	sub DESTROY
	{
		eval { 1 };
	}
}

{
	throws_ok {
		Bitcoin::Crypto::Exception->trap_into(
			sub { die 'test'; }
		);
	}
	"Bitcoin::Crypto::Exception", "exception was trapped";

	lives_and {
		is(
			Bitcoin::Crypto::Exception->trap_into(
				sub { 54321 }
			),
			54321
		);
	}
	"trapped return value ok";

	throws_ok {
		Bitcoin::Crypto::Exception->trap_into(
			sub {
				my $var = BuggyDestroy->new;
				die 'test';
			}
		);
	}
	"Bitcoin::Crypto::Exception", "exception was trapped despite DESTROY";

	note $@;
}

done_testing;

