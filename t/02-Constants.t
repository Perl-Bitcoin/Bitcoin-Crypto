use Test2::V0;
use Bitcoin::Crypto::Constants;

is Bitcoin::Crypto::Constants::curve_name, 'secp256k1', 'curve name ok';

done_testing;

