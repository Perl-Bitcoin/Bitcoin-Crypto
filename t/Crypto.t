use Modern::Perl "2010";
use Test::More;

BEGIN { use_ok('Bitcoin::Crypto', qw(version))};

like(Bitcoin::Crypto->VERSION(), qr/\d+\.\d+/, "version string ok");

done_testing;
