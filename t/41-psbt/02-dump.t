use v5.10;
use strict;
use warnings;
use Test::More;

use Bitcoin::Crypto qw(btc_psbt);

chomp(my $expected_v0 = <<PSBT);
Global map:
> PSBT_GLOBAL_UNSIGNED_TX:
> > 020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000
Input[0] map:
Input[1] map:
Output[0] map:
Output[1] map:
PSBT

chomp(my $expected_v2 = <<PSBT);
Global map:
> PSBT_GLOBAL_INPUT_COUNT:
> > 01
> PSBT_GLOBAL_OUTPUT_COUNT:
> > 02
> PSBT_GLOBAL_TX_VERSION:
> > 02000000
> PSBT_GLOBAL_VERSION:
> > 02000000
Input[0] map:
> PSBT_IN_OUTPUT_INDEX:
> > 00000000
> PSBT_IN_PREVIOUS_TXID:
> > 0b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8
Output[0] map:
> PSBT_OUT_AMOUNT:
> > 0008af2f00000000
> PSBT_OUT_SCRIPT:
> > 0014c430f64c4756da310dbd1a085572ef299926272c
Output[1] map:
> PSBT_OUT_AMOUNT:
> > 8bbdeb0b00000000
> PSBT_OUT_SCRIPT:
> > 00144dd193ac964a56ac1b9e1cca8454fe2f474f8513
PSBT

subtest 'should dump a version 0 PSBT' => sub {
	my $psbt = btc_psbt->from_serialized(
		[
			base64 =>
				'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA'
		]
	);

	is $psbt->dump, $expected_v0, 'psbt dump ok';
};

subtest 'should dump a version 2 PSBT' => sub {
	my $psbt = btc_psbt->from_serialized(
		[
			base64 =>
				'cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=='
		]
	);

	is $psbt->dump, $expected_v2, 'psbt dump ok';
};

done_testing;

