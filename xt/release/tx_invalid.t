# HARNESS-DURATION-LONG
use Test2::V0;

BEGIN {
	eval { require JSON::MaybeXS; 1 }
		or skip_all 'This test requires module JSON::MaybeXS';
}

use lib 't/lib';
use BitcoinCoreTest;

BitcoinCoreTest::test_tx('tx_invalid', !!0);

done_testing;

