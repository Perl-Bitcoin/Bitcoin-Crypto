use strict;
use warnings;

use Test::More tests => 13;
use Math::BigInt;

BEGIN { use_ok('Bitcoin::Crypto::Util', qw(validate_wif validate_address get_path_info)) };

# validate_wif - 3 tests

ok(validate_wif("935hpxoy4BGeuHmmtjURq52SehWtRoSArv6mJVZbVXUWyN9HQ5T"), "wif validation ok");
ok(!validate_wif("xyz"), "wif validation ok - invalid wif");
ok(!defined validate_wif("IOU"), "wif validation ok - invalid base58 wif");


# validate_address - 3 tests

ok(validate_address("mpyspBXHGvDMGiV6RpeWeVvSierBhysfdq"), "address validation ok");
ok(!validate_address("xyz"), "address validation ok - invalid address");
ok(!defined validate_address("IOU"), "address validation ok - invalid base58 address");

my @path_test_data = (
    [
        "m/0'/1/2/3'",
        {
            private => !!1,
            path => [
                2 << 30,
                1,
                2,
                3 + (2 << 30)
            ]
        }
    ],
    [
        "M/31311'/2/3",
        {
            private => !!0,
            path => [
                31311 + (2 << 30),
                2,
                3
            ],
        },
    ],
    [
        "m/0'/-1",
        undef
    ],
    [
        "M/m/1111",
        undef
    ],
    [
        "m/4500000000/1",
        undef
    ],
    [
        "M/1/2/4500000000'",
        undef
    ],
);


for my $case (@path_test_data) {
    is_deeply(get_path_info($case->[0]), $case->[1], "test case $case->[0]");
}
