use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# This code was used to produce this testnet transaction:
# https://mempool.space/testnet/tx/11cca738065ca9172394f800bab3f997698851fd0245848ec491b2744d1807e8

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

btc_utxo->extract(
	[
		hex =>
			'01000000000104381f7552e3ba01067333f2cf3321ceba15bb3077939c6133dcbc98df09870ca40000000000ffffffff5ba13b9c3180d36f24668f652e002640d1f51db48d7c2df4774a705befea6c6700000000171600140454b800857687eaee9bc68efc57c3598e3de4d9ffffffff27954badb0343f4335480d8d92d5e9853389bcb921fab9c2ddd495baebd1d89d0000000000ffffffff593d6ac408b55fa50c6747741b5867aab365a3f8fc3326e25bb4c4371fe2dba0010000001716001448087e9cf4495e34626a476aad75a2978e18d593ffffffff01493d020000000000160014216fdd3ff0d541788058d526d5ac7dc3c94f51cf0247304402205797f0cbca0b5e6151d2ee64bdf55f706f33683115ba5bcda382d328b526f06b022053ed5d5861481dc8af12c2a37da82c5e9c51cdf972e15743b7444adcc0a33b43012103355d2f5c6d699fe901ad79104c2abbbd362bbb2a2f6a8eca7e8d9cd140f4b7740247304402205b3cdc0912cdd8de191f1ed16d50b410930c029abbda8a7acf4eb9d52dbdb41102202966190e6727000fff320d36f2364d71790cd396dc72bc0fba21585daaa04ac40121021ca092cf73cad2b3c3549166ea404e033bed183491e15b7dd126d3be75c2893402483045022100a705a1b9cd1ca64743ef475444795cd8b76641710641826499e061246d0ae7bc02203c0f9fd28cb3ef49d55dcc40bea7a5f16a19be399b7f5444ec65c220178ed385012103019d0de5f90e8f5479089a4c2bc7f3704edb1c2b160c2682f33096b6c4c206b402483045022100e8527eefba1ce9f8db63af441d34e1fc4c364befec37599659d2e0fdfe33e9a80220671c8367a0d28ee722f213288829440947012ef5eacf428faff54d13168dd82a01210307755740cd57203167ead2eef17dabcd40e6e9853db31afca15072b107b98f7c00000000'
	]
);

$tx->add_input(
	utxo => [[hex => 'f8990964483b62a86ad1a5ae445b2d5b3ccd74c3611a857dc794a37eb5c62e3f'], 0],
);

$tx->add_output(
	locking_script => [P2WPKH => 'tb1qprasdghq2svf5hmta98zf93aj6z36ep7cpkj68'],
	value => 0,
);

$tx->add_output(
	locking_script => [NULLDATA => 'Have fun with Perl, use Bitcoin::Crypto!'],
	value => 0,
);

$tx->set_rbf;

# unsigned tx virtual size is used, so the real fee rate will be approx two times smaller
my $wanted_fee_rate = 2;
$tx->outputs->[0]->set_value($tx->fee - int($tx->virtual_size * $wanted_fee_rate));

btc_prv->from_wif('cVKqti7zi1P5zZ6yXhBxg6hRHtMAchdYPFfSmr5nMskiwUgzmfa8')->sign_transaction($tx, signing_index => 0);

$tx->verify;
say $tx->dump;
say to_format [hex => $tx->to_serialized];

