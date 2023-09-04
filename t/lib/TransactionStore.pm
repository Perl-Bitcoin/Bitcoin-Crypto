package TransactionStore;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto qw(btc_utxo btc_script);
use Bitcoin::Crypto::Util qw(to_format);

# Various UTXOs, needed in transaction tests

my %utxos = (
	'a34b7271d2add50bb6eaeaaaffaebe33bf4e3fe0454ca5d46ab64e6dbbbf1174;0' => {
		locking_script => [P2WPKH => 'bc1q7x7ua3s92k8gayvl8ltlqympxf53z075z486r2'],
		value => 198959,
	},
	'0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9;0' => {
		locking_script => [
			P2PK => [
				hex =>
					'0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3'
			]
		],
		value => 50_00000000,
	},
	'f483a885eb4ab57c2d1a5747d3be8ff83fa825ddaed2fd8176ed2cac9ee98fae;1' => {
		locking_script => [hex => '76a91415c055fa681fef5f8d342fc63b730648120679b388ac'],
		value => 1032575,
	},
	'94e519b9c0f43228e3dc841d838fc7372de95345206ef936ac6020889abe0457;0' => {
		locking_script => [hex => '76a9147df526887e47d6af7e89b35f8304dd2cf7519b3c88ac'],
		value => 1_19040000,
	},
	'94e519b9c0f43228e3dc841d838fc7372de95345206ef936ac6020889abe0457;1' => {
		locking_script => [hex => '76a914b8e6a6e0c0c5e62a49f1dbf8415cabb2f6ad0a6988ac'],
		value => 1_02119131,
	},
	'9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff;0' => {
		locking_script => [hex => '2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac'],
		value => 6_25000000,
	},
	'8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef;1' => {
		locking_script => [hex => '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'],
		value => 6_00000000,
	},
	'77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb;1' => {
		locking_script => [hex => 'a9144733f37cf4db86fbc2efed2500b4f4e49f31202387'],
		value => 10_00000000,
	},
	'5fb32a2b34f497274419100cfa8f79c21029e8a415936366b2b058b992f55fdf;5' => {
		locking_script => [P2PKH => '1C4mZbfHfLLEMJWd68WSaTZTPF2RFPYmWU'],
		value => 139615,
	},
	'81d5859d7db9b3d2da0fd4e8abd4b3005febb8fa72f0e4bd3687fd1863b1bd36;50' => {
		locking_script => [P2SH => '3HSZTsuakivAbX9cA7A6ayt6cf546WU6Bm'],
		value => 4_89995000,
	},
	'9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff;0' => {
		locking_script => [hex => '2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac'],
		value => 6_25000000,
	},
	'8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef;1' => {
		locking_script => [hex => '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'],
		value => 6_00000000,
	},
	'421b965bfa12d9d8ae17b23b346ca603c51602766fc639bdaf7284c5d7877f62;0' => {
		locking_script => [P2SH => '3NjkBnRi8BsiLtziBKNUmgsK7r8A1CLdjr'],
		value => 18093972,
	},
	'2586ccd8d12d8a2e88d76e7ba427ce5f123cbdc0fb14119109751826c9a53e78;0' => {
		locking_script => [P2PKH => '1AqD6yrAkeimM67p3rHvLTRnQvKVvEyAt6'],
		value => 858089,
	},
);

sub get_utxo
{
	my ($txid, $index) = @_;

	my $readable_txid = to_format [hex => $txid];
	if ($utxos{"$readable_txid;$index"}) {
		my $output = delete $utxos{"$readable_txid;$index"};
		return btc_utxo->new(
			txid => $txid,
			output_index => $index,
			output => $output,
		);
	}

	return undef;
}

btc_utxo->set_loader(\&get_utxo);

1;

