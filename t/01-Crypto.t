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
		sub { Bitcoin::Crypto->extprv },
	],
	[
		'Bitcoin::Crypto::Key::Private',
		\&btc_prv,
		sub { Bitcoin::Crypto->prv },
	],
	[
		'Bitcoin::Crypto::Key::ExtPublic',
		\&btc_extpub,
		sub { Bitcoin::Crypto->extpub },
	],
	[
		'Bitcoin::Crypto::Key::Public',
		\&btc_pub,
		sub { Bitcoin::Crypto->pub },
	],
	[
		'Bitcoin::Crypto::Script',
		\&btc_script,
		sub { Bitcoin::Crypto->script },
	],
);

foreach my $case (@cases) {
	my ($expected_package, @funcs) = @$case;

	subtest "testing $expected_package" => sub {
		foreach my $func (@funcs) {
			my $package = $func->();
			is $package, $expected_package;
		}
	}
}

done_testing;

