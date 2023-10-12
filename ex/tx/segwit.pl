use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# This code was used to produce this testnet transaction:
# https://mempool.space/testnet/tx/f8990964483b62a86ad1a5ae445b2d5b3ccd74c3611a857dc794a37eb5c62e3f

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

btc_utxo->extract(
	[
		hex =>
			'010000000001025c86bc8650181835c3853d685cf11f6fa42a8eb9e59cb25b2de64ae33ccdb9e00000000000ffffffffeb42cef4d898b0c1d93dd0aca91ef140ba2df35d5b722a18b2d88d3c255278de0000000000ffffffff021027000000000000160014dbabdc8a9a03e3e7268e7e87f99f1af235e7bebb4594000000000000160014df212a4c455f96199371a616ee30f9cd1b55c0b402483045022100e14daab47feff38dca3acbd04eb0036a1c64efdd3c5bd34c6a06a3612543422102201816503f77b3595fc7d829bbfd82282d9bc5b37bb7771070d0f7d74381fa8ccd0121037e01f2929a9219a7862fc25848a85df69b6a8ef49b7edbebfa64a095e136897d024730440220017703b6a4b0f6cc7799b0b7cae24f1a65188d0f40c28bb118b5c56de6f050ba022029f2e64ab5a6e9b04c07ac56bd46b07068d9ffe2b41fa6ff8f958d7dfa09be0c012103f97e2a442ed2bd4cb01fbf7c2ee8d0bd30dac47478671fb3a3bbef23ca57c71000000000'
	]
);

$tx->add_input(
	utxo => [[hex => 'a40c8709df98bcdc33619c937730bb15bace2133cff233730601bae352751f38'], 0],
);

btc_utxo->extract(
	[
		hex =>
			'01000000000101593d6ac408b55fa50c6747741b5867aab365a3f8fc3326e25bb4c4371fe2dba00000000000ffffffff02102700000000000017a91414f6d8848d031b6bb813866e2bcdd6608fb9c41b870745000000000000160014ce7b28a8445150159f98c2790b2ccdfb1767f59702483045022100a170dccb2bd8370edbd58c8a439203af6fe1d0101449469faa4ead2dcb2639a00220697ad9db7bf36f84aa8b1dc2c01eb2dedc070567581821e8272f41aa588fe04f0121024bd5b0fca10d2c8ade0dd2cbe868b4116d802d46d0898864c5c84253022e05e800000000'
	]
);

$tx->add_input(
	utxo => [[hex => '676ceaef5b704a77f42d7c8db41df5d14026002e658f66246fd380319c3ba15b'], 0],
);

btc_utxo->extract(
	[
		hex =>
			'010000000001033d97edd0856edc7655f9b42f9443efe1dbd596fc87cf45ab5c968a1165cfdd300000000000ffffffffd60af20e05a8de17e65ace71de6eae94c3f7f14c8aff65268467fb8d0b42f8370100000000ffffffff9958e77992d4b3576ddd6a371d04a5b5a732871ab630c0bb2aa76468cd725de70000000000ffffffff01b3c9010000000000160014f07d99d91cfa99a55ed583a45bc47309eded40cd0247304402202a4841b52238b2bccae3b69a5d204ce7a281ef73042880b83a241b012226a9c802204166961d6254faf17805c9f1b2a5c695074f17c452e7c077d3890bfd99e11749012103a7c8c7c76f85c8e65a378d64780a26b064c3955a6effb9f6cde9c885138cab9702483045022100e8d29e5cd7959a59b68f20cf814f71430a82d85dbe4a908cc9ac201c4bf8ae8902206c8d56bbd6bf01f5a45819358b322653c953d558517aaff1138fa28e4492008c012103eed605f9a9f7223492976ec80ccacc8ea280b9dae91702a9c9b416a6475cbd330247304402207c8fdd43e7dca55f84c2ab097dc93725b5505470d15c0d6dde4601a59727cfe20220566dfd0de5eed923c8f418e2ff3596009bc99afdd2c1e414aace7ae69a8671ee012103611606d82a61c22091485265c5285d02e165f3ee7ed72ffdbba45785f491ba4000000000'
	]
);

$tx->add_input(
	utxo => [[hex => '9dd8d1ebba95d4ddc2b9fa21b9bc893385e9d5928d0d4835433f34b0ad4b9527'], 0],
);

btc_utxo->extract(
	[
		hex =>
			'01000000000101381f7552e3ba01067333f2cf3321ceba15bb3077939c6133dcbc98df09870ca40100000000ffffffff02a66c000000000000160014163e48c26c6ce807b00b1400efbf72563838ea3e102700000000000017a91445fe03f2e3c7b6e962c696c0005e613b985a85cf870247304402202e64e2d158f201d2fdc14056629382a7ea3849b9415ec69659f6671c8a774bc7022075f7a32ba99e84605e5e4fc14d1e835be7c1c5a15d91d72d184f54fb7f89cf570121033b2e0f81f9e701f4474076378f1dae1bbd6a62342fd16e92a75832b85055b7cf00000000'
	]
);

$tx->add_input(
	utxo => [[hex => 'a0dbe21f37c4b45be22633fcf8a365b3aa67581b7447670ca55fb508c46a3d59'], 1],
);

$tx->add_output(
	locking_script => [P2WPKH => 'tb1qy9ha60ls64qh3qzc65ndttrac0y575w0m0lysn'],
	value => 0,
);

# unsigned tx virtual size is used, so the real fee rate will be approx two times smaller
my $wanted_fee_rate = 2;
$tx->outputs->[0]->set_value($tx->fee - int($tx->virtual_size * $wanted_fee_rate));

btc_prv->from_wif('cRdrKz5KKznsXDP33JiC187aRAvHvDkJPk4StLcQhfTSzgK6sciY')->sign_transaction($tx, signing_index => 0);
btc_prv->from_wif('cVHF9anUyf8mgVMH8CY4AdPB4AmictADwpLby1WMnS7SnKvzCaat')->sign_transaction($tx, signing_index => 1);
btc_prv->from_wif('cR3JQywaVoz1YtXhpSsgpaGq3juaQyrdv6C7xXjR91f3JRKKaG8T')->sign_transaction($tx, signing_index => 2);
btc_prv->from_wif('cPswC8N3dkykncfVQezhQbrbSWMwttuq7Zk9f5eH8Po5CCiHFQMd')->sign_transaction($tx, signing_index => 3);

$tx->verify;
say $tx->dump;
say to_format [hex => $tx->to_serialized];

