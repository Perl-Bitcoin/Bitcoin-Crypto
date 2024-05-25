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

	is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')],
		'020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000',
		'transaction field ok';

	is $psbt->input_count, 2, 'input count ok';
	is $psbt->output_count, 2, 'output count ok';
};

subtest 'getting a field from a non-existent input should not create it' => sub {
	$psbt->get_field('PSBT_IN_WITNESS_SCRIPT', index => 2);
	is $psbt->input_count, 2, 'input count ok';
};

done_testing;

