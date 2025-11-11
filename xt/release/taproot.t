# HARNESS-DURATION-LONG
use Test2::V0;

BEGIN {
	eval { require JSON::MaybeXS; 1 }
		or skip_all 'This test requires module JSON::MaybeXS';
}

use lib 't/lib';
use BitcoinCoreTest;

# test data from Bitcoin Core, mentioned in
# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#test-vectors
#
# test data was prepared as follows:
# - tests with pre-taproot serialization rules were adjusted or truncated
# - flags and final flag was truncated from each test to save space

BitcoinCoreTest::test_validation('taproot');

done_testing;

