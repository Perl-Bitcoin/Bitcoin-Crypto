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
		value => '50_00000000',
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
		value => '49_00000000',
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
	'464564320917d87c2398ad97b2b9e864fb5dde99f746263cc478bced35415680;0' => {
		locking_script => [P2PKH => '1FWQiwK27EnGXb6BiBMRLJvunJQZZPMcGd'],
		value => 7_69319495,
	},
	'f4d20cb42d857d6d056c3f09bd01094fee87a872f370d2b34a5661797bd225fe;2' => {
		locking_script => [P2TR => 'bc1pr7r8kpw9jhxy9fmtfda4le4g7mrmsfpmkmvpve74nhx9lxk59t6s57h27j'],
		value => 717362,
	},
	'c500442d44c1c0c37ed3f3184b61e0cb0c26dc17ffd6ad9331d9e2499581b5e5;0' => {
		locking_script => [P2TR => 'bc1p8kfnrkqxufj6rzh0y9mewnz90wjz8g3z3jqrpqg0ev35zzuas6ss20cvuw'],
		value => 600,
	},
	'c500442d44c1c0c37ed3f3184b61e0cb0c26dc17ffd6ad9331d9e2499581b5e5;1' => {
		locking_script => [P2TR => 'bc1p8kfnrkqxufj6rzh0y9mewnz90wjz8g3z3jqrpqg0ev35zzuas6ss20cvuw'],
		value => 600,
	},
	'20154a3f18faedfd185c56712c093fcb7cc8136a8287ef3261c7296fe54d8a3c;0' => {
		locking_script => [P2TR => 'bc1pchmlf82pwlgfqsngdh9hv5fe8txgd4chw06nsd0x4mqltx6qvp2qj8zf5h'],
		value => 546,
	},
	'c500442d44c1c0c37ed3f3184b61e0cb0c26dc17ffd6ad9331d9e2499581b5e5;2' => {
		locking_script => [P2TR => 'bc1p8kfnrkqxufj6rzh0y9mewnz90wjz8g3z3jqrpqg0ev35zzuas6ss20cvuw'],
		value => 1281179,
	},
	'dd40d3952d966eb74abf2b1bb97276b4d79511e0d480755aa3492de1207736bd;1' => {
		locking_script => [P2TR => 'bc1p60mm5chm8vnwxw7967jecswumv04yhjqd042zt28qt6t8rdqwyrsl087gs'],
		value => 777,
	},
	'e5f119d6665a5a9ef844e05442d1838f277d66bbf49a8e82e6882a14ada13875;0' => {
		locking_script => [P2TR => 'bc1pelw7fppkej6rmudv5uqllsflc0tzdpjxdm7hxyss7vu3qjtjqs2sx0nqqy'],
		value => 94726,
	},
	'a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec;0' => {
		locking_script => [P2TR => 'bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf'],
		value => 20000,
	},
	'44d275a5364b2430e7a8aa76d4b3235380fef79cf663dc544889c33208a20dc2;0' => {
		locking_script => [P2WPKH => 'bc1qj2uv8ft04sfpmhxll0y9kqhmnmmgzqu2zplyzu'],
		value => 999,
	},
	'8bc4f8facaaf7c4bdf6d77fac90aea208c2099a091d4b09658d002739daaad87;1' => {
		locking_script => [P2TR => 'bc1prwh247gy0nzzq4dr0gavnqda7l66h9h66rfdqlz5vz8g5xqmj3msh7uxx0'],
		value => 20000,
	},
	'd1c40446c65456a9b11a9dddede31ee34b8d3df83788d98f690225d2958bfe3c;0' => {
		locking_script => [P2TR => 'bc1p7dmcmml9zuafhackj463zc3yl9suq0rjts8f3wx63u2a72gefwqqku46c7'],
		value => 20000,
	},
	'ec7b0fdfeb2c115b5a4b172a3a1cf406acc2425229c540d40ec752d893aac0d7;0' => {
		locking_script => [P2TR => 'bc1pj7w0lxtrdksmpeylsug4znry9ajq68myxsxr0py5y2trdrad6zjsrfwpyj'],
		value => 10000,
	},
	'09347a39275641e291dff2d8beded236b6b1bb0f4a6ae40a50f67dce02cf7323;0' => {
		locking_script => [P2TR => 'bc1pveaamy78cq5hvl74zmfw52fxyjun3lh7lgt44j03ygx02zyk8lesgk06f6'],
		value => 1130279,
	},
	'777c998695de4b7ecec54c058c73b2cab71184cf1655840935cd9388923dc288;0' => {
		locking_script => [P2TR => 'bc1pveaamy78cq5hvl74zmfw52fxyjun3lh7lgt44j03ygx02zyk8lesgk06f6'],
		value => 30000,
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

