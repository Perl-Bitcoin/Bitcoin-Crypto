use strict;
use warnings;

use Test::More;
use Try::Tiny;
use Scalar::Util qw(blessed);

BEGIN { use_ok('Bitcoin::Crypto::Exception')};

local $SIG{__WARN__} = sub { die shift };

try {
	Bitcoin::Crypto::Exception->raise(code => "test_code", message => "test_message");
	fail("exception wasn't raised");
} catch {
	my $err = $_;
	ok(blessed $err, "object was created");
	ok($err->isa("Bitcoin::Crypto::Exception"), "object type ok");
	ok($err->is_exception, "it's an exception");
	is($err->code, "test_code", "code ok");
	is($err->message, "test_message", "message ok");
	ok("$err" =~ /test_message/, "class stringified");
	note("$err");
};

try {
	Bitcoin::Crypto::Exception->raise();
	fail("exception wasn't raised");
} catch {
	my $err = $_;
	ok(!blessed $err || !$err->isa("Bitcoin::Crypto::Exception"), "different exception was raised");
	note("$err");
};

try {
	Bitcoin::Crypto::Exception->warn(code => "test_code", message => "test_message");
	fail("warning wasn't raised");
} catch {
	my $err = $_;
	ok(blessed $err, "object was created");
	ok($err->isa("Bitcoin::Crypto::Exception"), "object type ok");
	ok(!$err->is_exception, "it's a warning");
	note("$err");
};

done_testing;

