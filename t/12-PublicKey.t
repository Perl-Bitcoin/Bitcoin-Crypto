use v5.10;
use strict;
use warnings;
use Test::More;
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto qw(btc_pub);

my @cases_compression = (
	{
		uncompressed =>
			'04394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967c52ad62fe0b27e5acc0992fc8509e5041a06064ce967200b0b7288a4ab889bf22',
		uncompressed_address => '16ixDtpj3JyKJUagRtLdhav76gw1MnrmsK',
		compressed => '02394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967c',
		compressed_address => '14wc2Jf5WoX1UZuwkb62acVRfNMwczjwDf',
	},
	{
		uncompressed =>
			'043992aa3f9deda22c02d05ca01a55d8f717d7464bb11ef43b59fc36c32613d0205f34f4ef398da815711d8917b804d429f395af403d52cd4b65b76839c88da442',
		uncompressed_address => '17MscEiRueoN9psHqV6oQGq8UWtdoaezSq',
		compressed => '023992aa3f9deda22c02d05ca01a55d8f717d7464bb11ef43b59fc36c32613d020',
		compressed_address => '16e5qefUVTiLxDuwpNTsJ7b3VL7rSmfYdc',
	},
);

my @cases_segwit = (
	{
		pubkey => '0332984aea6809830debe9f31dcb874b8b98a50b579d418184bf8ae55395c19567',
		compat_address => '38bKkt524L2KTr76kNapMxnnPF3RUt9skS',
		segwit_address => 'bc1qmhf3n5a06szyvp8yrr6ggcrpm3f7uyxsz62u29',
	},
	{
		pubkey => '025ac07e3c241a7062f6144815320b86c9557bd4de71f05a37c2c3c8012994ef80',
		compat_address => '34zCHfPoT8tdDuWBYEt7MxQKayDdmjnP1v',
		segwit_address => 'bc1qg35yd6pe7drgxzpyfzq6alm6xjukz9wxaw8s74',
	},
	{
		pubkey => '03d939f548ad09b3f9130b7567d7b27d6862651f3363bc68b15676da56f26c994d',
		compat_address => '35aWDrYGwEokTb22bYw2HbtXxySuAemo92',
		segwit_address => 'bc1qy2q5lgwt92y8fy2e9w9c8tpze2lej7f9rac5rl',
	},
	{
		pubkey => '0396aa08d4e14e4fd994f6618a4db40eb1f22b9368c6f4d48b77c43e1d852d6665',
		compat_address => '3MPiebrSnMLCEPr8NsEemwHY1oUrKCCRcL',
		segwit_address => 'bc1qvq5gcgfewz77lp6aa8uscwxkq4hf2xgjz7xf4w',
	},
	{
		pubkey => '02041cd51a1d0df8fba2dd5a87b1b08bc83cfbd4b2c605334629ed99d14a26c051',
		compat_address => '3NGaLfS945PVnYPMfhyDcgcohoXpEaW5Th',
		segwit_address => 'bc1q8u2wsar26p6z2r9ckh3t8xauhcm8sgzd2jzgkr',
	},
	{
		pubkey => '0367fc07d2a9d6b95305ea1bc33a3b693a5d0f9a6a90c2bac86c67e79808fcc98d',
		compat_address => '3EtNoU8L5Z2ikAVfGB1qf7UUFmGhASRkcM',
		segwit_address => 'bc1qfrxtzat3nutef828dr5ua7seq5d6selpued3dy',
	},
	{
		pubkey => '0332984aea6809830debe9f31dcb874b8b98a50b579d418184bf8ae55395c19567',
		compat_address => '38bKkt524L2KTr76kNapMxnnPF3RUt9skS',
		segwit_address => 'bc1qmhf3n5a06szyvp8yrr6ggcrpm3f7uyxsz62u29',
	},
	{
		pubkey => '03765fd0392d349415328fa40b83b05088d188b54b7b5d7a6a20124b70c17bc129',
		compat_address => '3KgwLH9P85yRFnN1f1sTrBTGXU6Ufek8sZ',
		segwit_address => 'bc1q5v4slm3x0pteg7n7ldefgsn9jpdkkg6e985vek',
	},
);

my %validation_case = (
	uncompressed =>
		'04b55965ca968e6e14d9175fb3fc3dc35f68b67b7e69cc2d1fa8c27f2406889c0f77cc2c39331735990bc67ccbf63c67642ff7b8ffd3794a4d76e0b78d9797a347',
	compressed => '03b55965ca968e6e14d9175fb3fc3dc35f68b67b7e69cc2d1fa8c27f2406889c0f',
	sig =>
		'3044022031731fbf940cffc6b72298b8775b12603fe16844a65983fb46b5fa8cf5d9e9bd022064625366f834314f8aef02aedc241a9b393d1f43887875f663b1be7080bae5c5',
);

my $case_num = 0;
foreach my $case (@cases_compression) {
	subtest "testing basic creation of keys, case $case_num" => sub {
		my $pubkey = btc_pub->from_serialized([hex => $case->{uncompressed}]);

		$pubkey->set_compressed(0);
		is(to_format [hex => $pubkey->to_serialized], $case->{uncompressed}, 'imported and exported correctly');
		is($pubkey->get_legacy_address, $case->{uncompressed_address}, 'correctly created address');

		$pubkey->set_compressed;
		is(to_format [hex => $pubkey->to_serialized], $case->{compressed}, 'exported compressed key correctly');
		is(
			$pubkey->get_legacy_address,
			$case->{compressed_address},
			'correctly created compressed address'
		);

		$pubkey->set_purpose(44);
		is(
			$pubkey->get_address,
			$case->{compressed_address},
			'correctly guessed legacy address'
		);
	};

	++$case_num;
}

$case_num = 0;
foreach my $case (@cases_segwit) {
	subtest "testing SegWit readiness, case $case_num" => sub {
		my $pubkey = btc_pub->from_serialized([hex => $case->{pubkey}]);

		is(
			$pubkey->get_compat_address,
			$case->{compat_address},
			'correctly created segwit compat address'
		);

		is(
			$pubkey->get_segwit_address,
			$case->{segwit_address},
			'correctly created segwit native address'
		);

		$pubkey->set_purpose(49);

		is(
			$pubkey->get_address,
			$case->{compat_address},
			'correctly guessed segwit compat address'
		);

		$pubkey->set_purpose(84);

		is(
			$pubkey->get_address,
			$case->{segwit_address},
			'correctly guessed segwit native address'
		);
	};

	++$case_num;
}

subtest 'verify message using pubkey' => sub {
	my $message = 'Perl test script';

	my $pub = btc_pub->from_serialized([hex => $validation_case{uncompressed}]);
	$pub->set_compressed(0);

	my $pub_compressed = btc_pub->from_serialized([hex => $validation_case{compressed}]);
	my $random_pub = btc_pub->from_serialized([hex => $cases_compression[0]{compressed}]);

	ok($pub->verify_message($message, [hex => $validation_case{sig}]), 'verified message correctly');
	ok(
		$pub_compressed->verify_message($message, [hex => $validation_case{sig}]),
		'compressed verified message correctly'
	);
	ok(
		!$random_pub->verify_message($message, [hex => $validation_case{sig}]),
		'verification fails with different pubkey'
	);
};

subtest 'generate addresses from non-default network' => sub {
	my $pub = btc_pub->from_serialized([hex => $validation_case{uncompressed}]);
	$pub->set_compressed(0);

	my $should_be_pub = $pub->set_network('bitcoin_testnet');
	is $should_be_pub, $pub, 'set_network return value ok';

	my $testnet_addr = 'n1raSqPwHRbJ87dC8daiwgLVrQBy9Fj17K';
	is($pub->network->name, 'Bitcoin Testnet', 'changed network to testnet');
	is($pub->get_legacy_address, $testnet_addr, 'created different address correctly');
};

done_testing;

