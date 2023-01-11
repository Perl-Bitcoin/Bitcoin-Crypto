use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto', qw(:all)) }

my %cases = (
	'Bitcoin::Crypto::Key::ExtPrivate' => \&btc_extprv,
	'Bitcoin::Crypto::Key::Private' => \&btc_prv,
	'Bitcoin::Crypto::Key::ExtPublic' => \&btc_extpub,
	'Bitcoin::Crypto::Key::Public' => \&btc_pub,
	'Bitcoin::Crypto::Script' => \&btc_script,

	'Bitcoin::Crypto::Key::ExtPrivate' => sub { Bitcoin::Crypto->extprv },
	'Bitcoin::Crypto::Key::Private' => sub { Bitcoin::Crypto->prv },
	'Bitcoin::Crypto::Key::ExtPublic' => sub { Bitcoin::Crypto->extpub },
	'Bitcoin::Crypto::Key::Public' => sub { Bitcoin::Crypto->pub },
	'Bitcoin::Crypto::Script' => sub { Bitcoin::Crypto->script },
);

while (my ($expected_package, $func) = each %cases) {
	my $package = $func->();
	is $package, $expected_package;
}

done_testing;

