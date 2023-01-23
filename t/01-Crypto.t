use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto', qw(:all)) }

my @cases = (
	[
		'Bitcoin::Crypto::Key::ExtPrivate',
		\&btc_extprv,
	],
	[
		'Bitcoin::Crypto::Key::Private',
		\&btc_prv,
	],
	[
		'Bitcoin::Crypto::Key::ExtPublic',
		\&btc_extpub,
	],
	[
		'Bitcoin::Crypto::Key::Public',
		\&btc_pub,
	],
	[
		'Bitcoin::Crypto::Script',
		\&btc_script,
	],
);

foreach my $case (@cases) {
	my ($expected_package, $func) = @$case;

	subtest "testing $expected_package" => sub {
		my $package = $func->();
		is $package, $expected_package;
	}
}

done_testing;

