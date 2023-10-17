use v5.10;
use strict;
use warnings;
use Test::More;
use Bitcoin::Crypto qw(btc_prv btc_transaction);
use Bitcoin::Crypto::Util qw(to_format);

use lib 't/lib';
use TransactionStore;

BEGIN {
	unless (btc_prv->HAS_DETERMINISTIC_SIGNATURES) {
		plan skip_all => 'These tests require Crypt::Perl 0.34';
	}
}

# this test case comes from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#user-content-Native_P2WPKH
my $tx = btc_transaction->from_serialized(
	[
		hex =>
			'0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000'
	]
);

btc_prv
	->from_serialized([hex => 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866'])
	->sign_transaction($tx, signing_index => 0)
	;

btc_prv
	->from_serialized([hex => '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9'])
	->sign_transaction($tx, signing_index => 1)
	;

is to_format [hex => $tx->to_serialized],
	'01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000',
	'deterministic signatures ok';

done_testing;

