use Modern::Perl "2010";
use Test::More;
use Test::Exception;
use Bitcoin::Crypto::Exception;

# partly tested by Bech32 tests
BEGIN { use_ok('Bitcoin::Crypto::Segwit', qw(validate_program)) };

# make warnings critical
local $SIG{__WARN__} = sub { die shift() . " - warning" };

# segwit version 1 program passing common length valiadion
my $program = "\x01\x00\xff";

{
	throws_ok {
		validate_program($program);
	} qr/- warning/, "warning was raised as exception";
	my $err = $@;

	note($err);
}

# use slightly changed validator from the documentation
$Bitcoin::Crypto::Segwit::validators{1} = sub {
	my ($data) = @_;

	# perform validation
	Bitcoin::Crypto::Exception::ValidationTest->raise(
		"validation of program version 1 failed"
	);

	# if validation is successful just do nothing
	return;
};

{
	throws_ok {
		validate_program($program);
	} "Bitcoin::Crypto::Exception::ValidationTest", "exception was raised";
	my $err = $@;

	note($err);
}

done_testing;
