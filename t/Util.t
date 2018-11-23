use strict;
use warnings;

use Test::More tests => 7;
use Math::BigInt;

BEGIN { use_ok('Bitcoin::Crypto::Util', qw(validate_wif validate_address)) };

# validate_wif - 3 tests

ok(validate_wif("935hpxoy4BGeuHmmtjURq52SehWtRoSArv6mJVZbVXUWyN9HQ5T"), "wif validation ok");
ok(!validate_wif("xyz"), "wif validation ok - invalid wif");
ok(!defined validate_wif("IOU"), "wif validation ok - invalid base58 wif");


# validate_address - 3 tests

ok(validate_address("mpyspBXHGvDMGiV6RpeWeVvSierBhysfdq"), "address validation ok");
ok(!validate_address("xyz"), "address validation ok - invalid address");
ok(!defined validate_wif("IOU"), "address validation ok - invalid base58 address");
