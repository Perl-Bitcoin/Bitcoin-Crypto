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
	'6eb316926b1c5d567cd6f5e6a84fec606fc53d7b474526d1fff3948020c93dfe;0' => {
		locking_script => [hex => '21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac'],
		value => 1_56250000,
	},
	'f825690aee1b3dc247da796cacb12687a5e802429fd291cfd63e010f02cf1508;0' => {
		locking_script => [hex => '00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0'],
		value => 49_00000000,
	},
	'01c0cf7fba650638e55eb91261b183251fbb466f90dff17f10086817c542b5e9;0' => {
		locking_script => [hex => '0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d'],
		value => 16777215,
	},
	'1b2a9a426ba603ba357ce7773cb5805cb9c7c2b386d100d1fc9263513188e680;0' => {
		locking_script => [hex => '0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537'],
		value => 16777215,
	},
	'eedb66e70c7b448fcb30f761dcc55cc63d08dbb17057c47095f8e29349f74164;0' => {
		locking_script => [P2PKH => '19V9nq4o6QcpCZaMwpWHtMoU5HUk19ueYH'],
		value => 50600000,
	},
	'667f6ebc1e965470b991f8b34f6cce1f4a6426d21167f3cc7ddea38a4eb9d562;1' => {
		locking_script => [P2PKH => '1KJztQoHCzZ2RyXmNF93BHTVoWiR9QfX1P'],
		value => 1000000,
	},
	'6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436;1' => {
		locking_script => [hex => 'a9149993a429037b5d912407a71c252019287b8d27a587'],
		value => 9_87654321,
	},
	'649aec7795d081ca823a8b80ff21374d7e953d9e450d29fb8723174b9bf389e9;3' => {
		locking_script => [P2SH => '3CxGtWTeiUAexHhCFUr6NATP1645xehE7M'],
		value => 96400,
	},
	'e07a307384cb06645f4634366d1ae150f03fc470f6badd7d0c510c4df1b774a9;23' => {
		locking_script => [P2SH => '3P6J7U53EK7mFw92VUqDCBxQsuZxq2y6qm'],
		value => 1288279,
	},
	'e4df37db4b8a214f37d9ea6128aa694fd61085b937629802fddd99cd04088070;1' => {
		locking_script => [P2WSH => 'bc1qg83pyg47edqd4jdu6vyjjcq3dahv68hpnwzpmvj53y44sv9vc75qdf2vpp'],
		value => 1_46697092,
	},
	'4c9346d5e71ad1c4066603c2b065180640d7eeac1b6194acf0c9ba9dc0cb7808;1' => {
		locking_script => [P2SH => '3N6xFHt5PFY1Lqy7gZhqWQ5aEE97R32qAo'],
		value => 16871417,
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

