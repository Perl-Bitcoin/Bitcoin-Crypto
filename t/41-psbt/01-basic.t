use v5.10;
use strict;
use warnings;
use Test::More;

use Bitcoin::Crypto qw(btc_psbt);
use Bitcoin::Crypto::Util qw(to_format);

my $psbt;

subtest 'should deserialize a version 0 PSBT' => sub {
	$psbt = btc_psbt->from_serialized(
		[
			base64 =>
				'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA'
		]
	);

	is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
		'82efd652d7ab1197f01a5f4d9a30cb4c68bb79ab6fec58dfa1bf112291d1617b',
		'transaction field ok';

	is $psbt->input_count, 2, 'input count ok';
	is $psbt->output_count, 2, 'output count ok';
};

subtest 'getting a field from a non-existent input should not create it' => sub {
	$psbt->get_field('PSBT_IN_WITNESS_SCRIPT', 2);
	is $psbt->input_count, 2, 'input count ok';
};

subtest 'should deserialize a version 2 PSBT' => sub {
	$psbt = btc_psbt->from_serialized(
		[
			base64 =>
				'cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=='
		]
	);

	is $psbt->input_count, 1, 'input count ok';
	is $psbt->output_count, 2, 'output count ok';
};

subtest 'should serialize any PSBT' => sub {
	is to_format [base64 => $psbt->to_serialized],
		'cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		'serialization ok';
};

done_testing;

