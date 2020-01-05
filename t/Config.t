use Modern::Perl "2010";
use Test::More;

BEGIN { use_ok('Bitcoin::Crypto::Config') };

ok(defined *config{HASH}, "config exported by default");

done_testing;
