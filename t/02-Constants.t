use v5.10;
use strict;
use warnings;
use Test::More;

BEGIN { use_ok('Bitcoin::Crypto::Constants') }

is Bitcoin::Crypto::Constants::curve_name, 'secp256k1', 'curve name ok';

done_testing;

