use strict;
use warnings;

use Test::More;
use Try::Tiny;

BEGIN { use_ok('Bitcoin::Crypto::ExtPublicKey') };

my %test_data = (
    "xpub661MyMwAqRbcFFM2R7nJTBxJ5SDygTLXPLFweie6ZaoskrEg4HPubXmNuHKtmoQrW1WyA67xtVTM5MsHzL2YHj7UYAMUWUKVawE6jtSCUNN" => [
        "1B39RJNGP6RdybznnXGnjnJTyPkf16XcBq",
        "1CJq9w2gjzsVdhXSEUzfpoCNGGVfe2mohP",
        "17RhDwe32qxGYKwCDUwgPMZEeenocWfChu",
    ],
    "xpub6AgWYrgHkcFKQUEkNCW7ZNwjnzwpJmV4eQizoWaJh44RQX58wyLvyxtDLPPBbotoX5ffiY4dmDcSYk3xGd59BSgChqEtGoaNm9TNfEEAN4x" => [
        "1En7YxSy9xNTRCphNKwbKWvoJt8rDq5TPF",
        "13gyhuHZTFGVHphYGAKzXEtGFnHZjfwsbu",
        "1EjfmS2yvQAtJM4Te2UvEAiV4uX5vzfxLu",
        "1N4ZpQ8YSMJ3kzY96fEiGFFKPxVj4UP1LB",
    ],
    "xpub6AgWYrgHkcHfM9Qq834SHknHeJGWLQXzFiXkBansYdUdhReFr2Zd3FXjjeWYXLs3R96d8XQqg6fgSbvrJG4DYZyjRTXvgLTCSbDuodKuyGe" => [
        "1M1FL5Y5U8Y6P9nPgnoD8wHSKU3UbZDijT",
        "12cpYB97BwVsr1kbyZtda5tpTxo7TpCT5p",
        "18YvBL76LjpJwdJ88Z6DDH8FcPcR1Mbzaa",
    ]
);

my $tests = 1;

for my $ser_key (keys %test_data) {
    my $addresses = $test_data{$ser_key};
    my $master_pubkey = Bitcoin::Crypto::ExtPublicKey->fromSerializedBase58($ser_key);
    for my $i (0 .. @$addresses - 1) {
        $tests += 1;
        my $derived = $master_pubkey->deriveKey("M/$i");
        is($derived->getBasicKey()->getAddress(), $addresses->[$i], "address is valid");
    }
}

done_testing($tests);
