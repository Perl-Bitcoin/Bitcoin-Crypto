use v5.10; use warnings;
use Test::More;
use Test::Exception;
use Module::Loaded;

BEGIN { use_ok('Bitcoin::Crypto', qw(:all))};

like(Bitcoin::Crypto->VERSION(), qr/\d+\.\d+/, "version string ok");

my %cases = (
	"Bitcoin::Crypto::Key::ExtPrivate" => \&btc_extprv,
	"Bitcoin::Crypto::Key::Private" => \&btc_prv,
	"Bitcoin::Crypto::Key::ExtPublic" => \&btc_extpub,
	"Bitcoin::Crypto::Key::Public" => \&btc_pub,
	"Bitcoin::Crypto::Script" => \&btc_script,
);

for my $package (keys %cases) {
	ok !is_loaded($package), "can't use $package yet";
}

while (my ($expected_package, $func) = each %cases) {
	my $package = $func->();
	is $package, $expected_package;
	ok is_loaded($package), "can use $package - was loaded";
}

done_testing;
