# HARNESS-DURATION-LONG
use Test2::V0;

BEGIN {
	eval { require JSON::MaybeXS; 1 }
		or skip_all 'This test requires module JSON::MaybeXS';
}

use lib 't/lib';
use BitcoinCoreTest;

BitcoinCoreTest::test_script('script_tests');

done_testing;

