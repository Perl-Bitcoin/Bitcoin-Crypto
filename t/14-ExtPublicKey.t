use v5.10;
use strict;
use warnings;
use Test::More;

use Bitcoin::Crypto qw(btc_extpub);

my @cases = (
	{
		key =>
			'xpub661MyMwAqRbcFFM2R7nJTBxJ5SDygTLXPLFweie6ZaoskrEg4HPubXmNuHKtmoQrW1WyA67xtVTM5MsHzL2YHj7UYAMUWUKVawE6jtSCUNN',
		addresses => [
			'1B39RJNGP6RdybznnXGnjnJTyPkf16XcBq',
			'1CJq9w2gjzsVdhXSEUzfpoCNGGVfe2mohP',
			'17RhDwe32qxGYKwCDUwgPMZEeenocWfChu',
		],
	},

	{
		key =>
			'xpub6AgWYrgHkcFKQUEkNCW7ZNwjnzwpJmV4eQizoWaJh44RQX58wyLvyxtDLPPBbotoX5ffiY4dmDcSYk3xGd59BSgChqEtGoaNm9TNfEEAN4x',
		addresses => [
			'1En7YxSy9xNTRCphNKwbKWvoJt8rDq5TPF',
			'13gyhuHZTFGVHphYGAKzXEtGFnHZjfwsbu',
			'1EjfmS2yvQAtJM4Te2UvEAiV4uX5vzfxLu',
			'1N4ZpQ8YSMJ3kzY96fEiGFFKPxVj4UP1LB',
		],
	},

	{
		key =>
			'xpub6AgWYrgHkcHfM9Qq834SHknHeJGWLQXzFiXkBansYdUdhReFr2Zd3FXjjeWYXLs3R96d8XQqg6fgSbvrJG4DYZyjRTXvgLTCSbDuodKuyGe',
		addresses => [
			'1M1FL5Y5U8Y6P9nPgnoD8wHSKU3UbZDijT',
			'12cpYB97BwVsr1kbyZtda5tpTxo7TpCT5p',
			'18YvBL76LjpJwdJ88Z6DDH8FcPcR1Mbzaa',
		],
	},
);

my $case_num = 0;
for my $case (@cases) {
	subtest "testing deserialization and addresses, case $case_num" => sub {
		my $master_pubkey = btc_extpub->from_serialized([base58 => $case->{key}]);
		for my $i (0 .. @{$case->{addresses}} - 1) {
			my $derived = $master_pubkey->derive_key("M/$i");
			is($derived->get_basic_key()->get_legacy_address(), $case->{addresses}[$i], 'address is valid');
		}
	};

	++$case_num;
}

done_testing;

