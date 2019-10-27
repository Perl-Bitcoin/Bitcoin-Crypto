use strict;
use warnings;

use Test::More;
use Try::Tiny;
use Scalar::Util qw(blessed);
use Bitcoin::Crypto::Exception;

# partly tested by Bech32 tests
BEGIN { use_ok('Bitcoin::Crypto::Segwit', qw(validate_program)) };

# make warnings critical
local $SIG{__WARN__} = sub { die shift };

# segwit version 1 program passing common length valiadion
my $program = "\x01\x00\xff";

try {
	validate_program($program);
	fail("nothing was reported");
} catch {
	my $err = $_;

	ok(blessed $err, "object was raised");
	ok($err->isa("Bitcoin::Crypto::Exception"), "object type ok");
	ok(!$err->is_exception, "it's a warning");

	is($err->code, "segwit_program", "warning code ok");
	note($err->message);
};

# use slightly changed validator from the documentation
$Bitcoin::Crypto::Segwit::validators{1} = sub {
	my ($data) = @_;

	# perform validation
	Bitcoin::Crypto::Exception->raise(
		code => "validation_test",
		message => "validation of program version 1 failed"
	);

	# if validation is successful just do nothing
	return;
};

try {
	validate_program($program);
	fail("nothing was reported");
} catch {
	my $err = $_;

	ok(blessed $err, "object was raised");
	ok($err->isa("Bitcoin::Crypto::Exception"), "object type ok");
	ok($err->is_exception, "it's an error");

	is($err->code, "validation_test", "error code ok");
	note($err->message);
};

done_testing;
