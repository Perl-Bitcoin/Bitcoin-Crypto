use v5.10; use warnings;
use Test::More;

BEGIN { use_ok('Bitcoin::Crypto::Config') }

ok(defined *config{HASH}, "config exported by default");

done_testing;
