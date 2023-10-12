use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv btc_script);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# This code was used to produce this testnet transaction:
# https://mempool.space/testnet/tx/59eb3933d805ca4d75f0ffcf9323a4588903d8d11d9942ed6d5f7e1298621518

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

btc_utxo->extract(
	[
		hex =>
			'010000000001013f2ec6b57ea394c77d851a61c374cd3c5b2d5b44aea5d16aa8623b48640999f80000000000fdffffff023f3c02000000000016001408fb06a2e054189a5f6be94e24963d96851d643e00000000000000002a6a28486176652066756e2077697468205065726c2c2075736520426974636f696e3a3a43727970746f21024830450221008f7e3620e71b6d3f392c5f83c3f3c0a898fe4d261addba0a11e2efea5400eed402205f0e4ab6672fe96df08c622e111f70866a9e869b4fcae399dc3dda3ae4b4ad8001210269b7f4598f42b107483ff2360b70f48c47fb072afbf9a74ec02cf5dc8997c70300000000'
	]
);

$tx->add_input(
	utxo => [[hex => '11cca738065ca9172394f800bab3f997698851fd0245848ec491b2744d1807e8'], 0],
);

# this is the actual multisig script which will lock the coins.
# Note: this will be required to redeem the coins. Don't lose it!
my $nested_script = btc_script->from_standard(
	P2MS => [
		2,
		[hex => '0351d02712ec3702786bb1deb2e56417ecef2bd358090c9636f73a0e651153ac60'],
		[hex => '03ec1449d401d94b78dc0127aa4eaed6a2e7a6a6b11fb9243e97b38373a8ded90d'],
		[hex => '028875dc1d1d3f672543bb75c320e29b7bbc103329f44064b2d47a3cddc757c184'],
	]
);

# P2WSH is a standard way to nest multisig. Legacy P2SH could also be used
$tx->add_output(
	locking_script => [P2WSH => $nested_script->get_segwit_address],
	value => 0,
);

$tx->set_rbf;
$tx->outputs->[0]->set_value($tx->fee - 200);

btc_prv->from_wif('cTTuo7it8LTWHhnGmodkK7ZA75NTcx5Mu87pGgPi7x1N9Gg4a9m3')->sign_transaction($tx, signing_index => 0);

$tx->verify;
say $tx->dump;
say to_format [hex => $tx->to_serialized];

