use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use Bitcoin::Crypto::Exception;

# partly tested by Bech32 tests
BEGIN { use_ok('Bitcoin::Crypto::Segwit', qw(validate_program)) }

# make warnings critical
local $SIG{__WARN__} = sub { die shift() . ' - segwit test warn' };

# segwit version 15 program passing common length valiadion
my $program = "\x0f\x00\xff";

subtest 'validate segwit version 15 program without validator specified' => sub {
	throws_ok {
		validate_program($program);
	} qr/segwit test warn/, 'warning was raised as exception';
};

subtest 'validate segwit version 15 program with validator specified' => sub {
	# use slightly changed validator from the documentation
	local $Bitcoin::Crypto::Segwit::validators{15} = sub {
		my ($data) = @_;

		# perform validation
		Bitcoin::Crypto::Exception::ValidationTest->raise(
			'validation of program version 15 failed'
		);

		# if validation is successful just do nothing
		return;
	};

	throws_ok {
		validate_program($program);
	} 'Bitcoin::Crypto::Exception::ValidationTest', 'exception was raised';
};

done_testing;

