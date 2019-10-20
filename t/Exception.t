use strict;
use warnings;

use Test::More;
use Try::Tiny;

BEGIN { use_ok('Bitcoin::Crypto::Exception')};

try {
	Bitcoin::Crypto::Exception->raise(code => "test_code", message => "test_message");
	fail("exception wasn't raised");
} catch {
	my $err = $_;
	ok($err->isa("Bitcoin::Crypto::Exception"), "object was created");
	is($err->code, "test_code", "code ok");
	is($err->message, "test_message", "message ok");
	ok("$err" =~ /test_message/, "class stringified");
	note("$err");
};

done_testing;

