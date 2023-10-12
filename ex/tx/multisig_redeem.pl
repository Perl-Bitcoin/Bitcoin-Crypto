use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv btc_script);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# This code was used to produce this testnet transaction:
# https://mempool.space/testnet/tx/8077dbb8ee049a5a754ad5e681310c1ee192e9be44a3b76d1182b41f1d39c2f5

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

btc_utxo->extract(
	[
		hex =>
			'01000000000101e807184d74b291c48e844502fd51886997f9b3ba00f8942317a95c0638a7cc110000000000fdffffff01773b02000000000022002021751bfd57081ee0e93902a82db2b0d6540ca1858fdf5f309a35086d3635ad6602483045022100e2d6cb6ac427d1116174e4b22cad24039c4434cfffd32dc9da537365e071076d02201f93b599c983a9f618eef0096a0ae370a2a8ec717d6f076d99991997fbf6da7d012103dde6306f456d48dd13cb24e4ec98a9f15b7904457852429098df4c0f68cddb3900000000'
	]
);

$tx->add_input(
	utxo => [[hex => '59eb3933d805ca4d75f0ffcf9323a4588903d8d11d9942ed6d5f7e1298621518'], 0],
);

$tx->add_output(
	locking_script => [P2WPKH => 'tb1qg3kknh2wyg3agcxwwtr44tzea40v550apucx76'],
	value => 0,
);

$tx->set_rbf;
$tx->outputs->[0]->set_value($tx->fee - 300);

# $redeem_script is required for P2WSH (this was not yet published on
# the blockchain, only its hash)
my $redeem_script = btc_script->from_standard(
	P2MS => [
		2,
		[hex => '0351d02712ec3702786bb1deb2e56417ecef2bd358090c9636f73a0e651153ac60'],
		[hex => '03ec1449d401d94b78dc0127aa4eaed6a2e7a6a6b11fb9243e97b38373a8ded90d'],
		[hex => '028875dc1d1d3f672543bb75c320e29b7bbc103329f44064b2d47a3cddc757c184'],
	]
);

# sign using the private key belonging to the first pubkey
btc_prv->from_wif('cScAuqNfiNR7mq61QGW3LtokKAwzBzs4rbCz4Uff1NA15ysEij2i')
	->sign_transaction($tx, signing_index => 0, redeem_script => $redeem_script, multisig => [1, 2]);

# sign using the private key belonging to the third pubkey
btc_prv->from_wif('cQsSKWrBLXNY1oSZbLcJf4HF5vnKGgKko533LnkTmqRdS9Fx4SGH')
	->sign_transaction($tx, signing_index => 0, redeem_script => $redeem_script, multisig => [2, 2]);

# since the multisig requirements were exhausted (2 out of 2 required
# signatures), the transaction is ready

$tx->verify;
say $tx->dump;
say to_format [hex => $tx->to_serialized];

