use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv btc_script);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# This code was used to produce this testnet transaction:
# https://mempool.space/testnet/tx/4cb7af0ac5c964ebe2bc6aa0bcf2b96193d8cfa2fd6a77c0a5f0f3276f3c3f69

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

btc_utxo->extract(
	[
		hex =>
			'010000000001035c86bc8650181835c3853d685cf11f6fa42a8eb9e59cb25b2de64ae33ccdb9e00100000000ffffffff68bf7aebf476905ca6c64157f4db022bcf1c2bf5ce307e87e29eb85609e234f10000000000ffffffff43248a3d400f077e56c9fb4ad4eeffb7f40f4c47dc7d6a5e1aa73af54b659c600100000000ffffffff014273000000000000160014446d69dd4e2223d460ce72c75aac59ed5eca51fd02483045022100c49c615ec905a43ef3e3ade777cd88d5edfbf0cc73a767d3ba5de93ba3c79baa02204bd87a6f9fe5ea8440af473575a878202bc158dd2e2211806aae06af8314a936012102b0dc2c2532e8caec0834dc3a2e5f0b75df4d21bfae1993ef29f9693b1f2e2c9b024730440220785627af9f94705a16bdbab2e622c6679902dcb3c3a78d9ddd3d6fab8018322f022045c855dafc5991c5d7be3ca5a167ff72719262c5aca15d4499f2f11c066a1b3401210390ec05ed848aa312fb8b06e41475a3b38db61b0bab47b5aedab6d806c8f0222202483045022100de0fe732000f96b99afcc608c03fc941f5658714eabad178889b92c17c77a7be02205f9cc9514ad515be53c6d77714fe72f0f954ff24b14c7828f6d3ec0b21967fb701210390ec05ed848aa312fb8b06e41475a3b38db61b0bab47b5aedab6d806c8f0222200000000'
	]
);

$tx->add_input(
	utxo => [[hex => '761c4e34ab0d690bb2cf4a2aed1eaaab531a8f82e2cf5ab7de2823118a8d9bc6'], 0],
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
	locking_script => [P2SH => $nested_script->get_compat_address],
	value => 0,
);

$tx->set_rbf;
$tx->outputs->[0]->set_value($tx->fee - 200);

btc_prv->from_wif('cMzqhSf7jrfvZhG8VNSTvGsJjGq6LXgSuuKGMBMnuRUvpgVGz3Wk')->sign_transaction($tx, signing_index => 0);

$tx->verify;
say $tx->dump;
say to_format [hex => $tx->to_serialized];

