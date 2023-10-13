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
			'01000000000101c69b8d8a112328deb75acfe2828f1a53abaa1eed2a4acfb20b690dab344e1c760000000000fdffffff017a7200000000000017a9145112462c957afd56304e94297e2715adf33ffa778702483045022100f96bd192f5084c13610af1a098fcc4d4be349fb808aa5ad54f51dde4ac32649c02203ee0063df18bb5a520c6ef62e26510ef3151f4a7f265f8eedc8ea08c027d59b10121031c8df48de83ffc5edece85dfd944b1920f443923fee6421a106c16f4868dbb2700000000'
	]
);

$tx->add_input(
	utxo => [[hex => '4cb7af0ac5c964ebe2bc6aa0bcf2b96193d8cfa2fd6a77c0a5f0f3276f3c3f69'], 0],
);

btc_utxo->extract(
	[
		hex => '0100000000010118156298127e5f6ded42991dd1d8038958a42393cffff0754dca05d83339eb590000000000fdffffff014b3a020000000000160014446d69dd4e2223d460ce72c75aac59ed5eca51fd0400483045022100af107ba43245f68f8c9e91b72d5abc96b8cfc50282658e5a120cf3f86df2f0cf02203c091bb66dddeda66c990c564e5bbf62464815b2bfdc2c839aaa22969a34b75801473044022056297a7026395f7684106a72ce147965d91800f79b526c29cd2435899064fbe80220756d591bdd0ba9acce4adfc6d4a8b767b85eea4f098f933ac864f5e339a84d2e016952210351d02712ec3702786bb1deb2e56417ecef2bd358090c9636f73a0e651153ac602103ec1449d401d94b78dc0127aa4eaed6a2e7a6a6b11fb9243e97b38373a8ded90d21028875dc1d1d3f672543bb75c320e29b7bbc103329f44064b2d47a3cddc757c18453ae00000000'
	]
);

$tx->add_input(
	utxo => [[hex => '8077dbb8ee049a5a754ad5e681310c1ee192e9be44a3b76d1182b41f1d39c2f5'], 0],
);

$tx->add_output(
	locking_script => [P2WPKH => 'tb1qyzsk50r2uxtcnclclkp3s6ujtg85af0x2vz7lr'],
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
# signatures), the only thing left is to sign the second output

btc_prv->from_wif('cMzqhSf7jrfvZhG8VNSTvGsJjGq6LXgSuuKGMBMnuRUvpgVGz3Wk')->sign_transaction($tx, signing_index => 1);

$tx->verify;
say $tx->dump;
say to_format [hex => $tx->to_serialized];

