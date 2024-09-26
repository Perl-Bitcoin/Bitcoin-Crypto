use Test2::V0;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Encode qw(encode);

use Bitcoin::Crypto::Util qw(:all);
use Bitcoin::Crypto::Helpers;    # loads Math::BigInt
use Bitcoin::Crypto::Key::ExtPrivate;

subtest 'testing mnemonic_to_seed' => sub {
	is mnemonic_to_seed(
		'われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　らいう',
		'㍍ガバヴァぱばぐゞちぢ十人十色'
		),
		pack(
			'H*',
			'a44ba7054ac2f9226929d56505a51e13acdaa8a9097923ca07ea465c4c7e294c038f3f4e7e4b373726ba0057191aced6e48ac8d183f3a11569c426f0de414623'
		),
		'seed from mnemonic ok';
};

subtest 'testing validate_wif' => sub {
	my @cases = (
		['935hpxoy4BGeuHmmtjURq52SehWtRoSArv6mJVZbVXUWyN9HQ5T' => !!1],
		['Aammc6SScZZF47CuWe4Wn91kDE' => !!0],
		['IOU' => undef],
	);

	foreach my $case (@cases) {
		my ($to_test, $result) = @$case;
		if (defined $result) {
			ok lives {
				is(validate_wif($to_test), $result)
			}, 'wif validation ok';
		}
		else {
			isa_ok dies {
				validate_wif($to_test);
			}, 'Bitcoin::Crypto::Exception';
		}
	}
};

subtest 'testing get_path_info' => sub {
	my @path_test_data = (
		[
			"m/0'/1/2/3'",
			{
				private => !!1,
				path => [
					2 << 30,
					1,
					2,
					3 + (2 << 30)
				]
			}
		],
		[
			"M/31311'/2/3",
			{
				private => !!0,
				path => [
					31311 + (2 << 30),
					2,
					3
				],
			},
		],
		[
			"m/0'/-1",
			undef
		],
		[
			"M/m/1111",
			undef
		],
		[
			"m/4500000000/1",
			undef
		],
		[
			"M/1/2/4500000000'",
			undef
		],
	);

	for my $case (@path_test_data) {
		isa_ok(get_path_info($case->[0]), 'Bitcoin::Crypto::DerivationPath')
			if defined $case->[1];
		is(get_path_info($case->[0]), $case->[1], "test case $case->[0]");
	}
};

subtest 'testing hash160 / hash256' => sub {
	my $data = pack 'u', 'packed data...';
	is(hash160($data), ripemd160(sha256($data)), 'hash160 ok');
	is(hash256($data), sha256(sha256($data)), 'hash256 ok');
};

subtest 'testing mnemonic_from_entropy' => sub {
	my $entropy = pack 'H*', '26994a6f6097b7d3615e7dc17ba10e580755ad034e3b4fa0a55de5aba652cb66';
	my $mnemonic = mnemonic_from_entropy($entropy);

	is $mnemonic,
		'charge ski orange scorpion kiwi trust lyrics soul scrap tackle drum quote inspire story artwork shuffle exile ahead first slender risk city collect silver';

	isa_ok dies {
		my $mnemonic = mnemonic_from_entropy("\x01" x 17, 'en');
	}, 'Bitcoin::Crypto::Exception::MnemonicGenerate';
};

subtest 'testing generate_mnemonic / mnemonic_from_entropy' => sub {

	# generating english mnemonics
	for my $bits (map { 128 + $_ * 32 } 0 .. 4) {
		my @mnemonics = (
			generate_mnemonic($bits, 'en'),
			mnemonic_from_entropy("\x01" x ($bits / 8), 'en'),
		);

		foreach my $mnemonic (@mnemonics) {
			my $length = $bits / 8 - 4;
			ok($mnemonic =~ /^(\w+ ?){$length}$/, "generated mnemonic looks valid ($bits bits)");
			ok lives {
				Bitcoin::Crypto::Key::ExtPrivate->from_mnemonic($mnemonic, '', 'en');
			}, 'generated mnemonic can be imported';
		}
	}

	isa_ok dies {
		my $mnemonic = generate_mnemonic(129, 'en');
	}, 'Bitcoin::Crypto::Exception::MnemonicGenerate';

};

subtest 'testing get_address_type' => sub {
	is get_address_type('1AshirGYwnrFsN82DpV83NDfQpRJMuXxLQ'), 'P2PKH', 'P2PKH ok';
	is get_address_type('3HDtyBHZ4111BFtUBY2SA4eXJQxifmaTYw'), 'P2SH', 'P2SH ok';
	is get_address_type('bc1q73vqlq8ptpjhd4pnghqq0gvn3nqh4tn00utypf'), 'P2WPKH', 'P2WPKH ok';
	is get_address_type('bc1qxrv57xwn050dht30kt9msenkqf67rh0cjcurhukznucjwk63xm3skajjcc'), 'P2WSH', 'P2WSH ok';
	is get_address_type('bc1pag3474cedulvygrj0xlk77lr94dnknx4yl5ygawkcwe2dq5gq7xqjxwe5q'), 'P2TR', 'P2WSH ok';

	ok dies {
		get_address_type('aoreduroadeuro');
	}, 'random letters not an address';

	ok dies {
		get_address_type('');
	}, 'empty string not an address';

	ok dies {
		get_address_type('tb1q26jy9d4vkfqezh6hm7qp7txvk8nggkwv2y72x0');
	}, 'testnet address not on mainnet';

	is get_address_type('tb1q26jy9d4vkfqezh6hm7qp7txvk8nggkwv2y72x0', 'bitcoin_testnet'), 'P2WPKH',
		'network param ok';
};

# segwit program passing common length valiadion (no version)
my $program = "\x55\xff\x33";

subtest 'should fail validation of segwit version 0 program' => sub {
	isa_ok dies {
		validate_segwit("\x00" . $program);
	}, 'Bitcoin::Crypto::Exception::SegwitProgram';
};

subtest 'should pass validation of segwit version 1 program' => sub {
	ok lives {
		validate_segwit("\x01" . $program);
	};
};

subtest 'should pass validation of segwit version 15 program' => sub {
	ok lives {
		validate_segwit("\x0f" . $program);
	};
};

subtest 'testing to_format' => sub {
	is to_format [bytes => "\x00\xff\x55"], "\x00\xff\x55", 'should handle bytes';
	is to_format [hex => "\x00\xff\x55"], '00ff55', 'should handle hex';
	is to_format [base58 => "\x00\xff\x55"], '13C9fhDMSM', 'should handle base58';
	is to_format [base64 => "\x00\xff\x55"], 'AP9V', 'should handle base64';
};

subtest 'testing from_format' => sub {
	is from_format [bytes => "\x00\xff\x55"], "\x00\xff\x55", 'should handle bytes';
	is from_format [hex => '00ff55'], "\x00\xff\x55", 'should handle hex';
	is from_format [base58 => '13C9fhDMSM'], "\x00\xff\x55", 'should handle base58';
	is from_format [base64 => 'AP9V'], "\x00\xff\x55", 'should handle base64';
};

subtest 'testing compactsize one byte' => sub {
	is pack_compactsize(128), "\x80", 'packing ok';
	is unpack_compactsize("\x80"), 128, 'unpacking ok';
};

subtest 'testing compactsize one byte (high)' => sub {
	is pack_compactsize(255), "\xfd\xff\x00", 'packing ok';
	is unpack_compactsize("\xfd\xff\x00"), 255, 'unpacking ok';
};

subtest 'testing compactsize two bytes' => sub {
	is pack_compactsize(515), "\xfd\x03\x02", 'packing ok';
	is unpack_compactsize("\xfd\x03\x02"), 515, 'unpacking ok';
};

subtest 'testing compactsize four bytes' => sub {
	is pack_compactsize(75105), "\xfe\x61\x25\x01\x00", 'packing ok';
	is unpack_compactsize("\xfe\x61\x25\x01\x00"), 75105, 'unpacking ok';
};

subtest 'testing compactsize eight bytes' => sub {
	plan skip_all => 'requires 64 bit system'
		unless Bitcoin::Crypto::Constants::is_64bit;

	is pack_compactsize(7451076510762517), "\xff\x15\x46\x9e\xf0\xb6\x78\x1a\x00", 'packing ok';
	is unpack_compactsize("\xff\x15\x46\x9e\xf0\xb6\x78\x1a\x00"), 7451076510762517, 'unpacking ok';
};

subtest 'testing unpack_compactsize with pos argument' => sub {
	my $pos = 2;
	is unpack_compactsize("\x00\x00\xfe\x61\x25\x01\x00\x00", \$pos), 75105, 'unpacking ok';
	is $pos, 7, 'position ok';
};

subtest 'testing unpack_compactsize with leftover data' => sub {
	isa_ok dies {
		unpack_compactsize("\xfe\x61\x25\x01\x00\x00");
	}, 'Bitcoin::Crypto::Exception';
};

subtest 'testing merkle_root' => sub {
	my $block_100022 = [
		[
			hex =>
				'01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b017effffffff0100f2052a0100000043410445f2f386053a166fcb87ce65dd352c8b4aa0a75037a83a4120d75617c48c67e9d167325da1e4f45770bf5a7b69cce1ec9fe9a96b74ffd3d5453246636178ab83ac00000000'
		],
		[
			hex =>
				'010000000111c8c3eb08ce6c4c06e0929ae6f07e20ef8430a2bd363c3abe16c6123572092e0000000049483045022100cb13fb12ebfec97b7e2c6b0da5cc01f6560d53572997ebefe16384b8cca07c620220281366068fd6bd695cce114fc2652a56443ec5d6697cddef395f14f6a416018c01ffffffff0100f2052a010000001976a91408903a156dd0cd5c96b07568cefda2217a18a85988ac00000000'
		],
		[
			hex =>
				'0100000001c14d63abdba0823b78fb558e9b35f3fc166b73a6c3ebe05dc98bcfaf75ad0909010000008a47304402206ebe92a1082344a693b9a036fdee0e61f9b450b0a27b11cad9c51700cacdeef902207a6a19dd92cb394f8a4d5da113b6f3b2486703767b3ab36ddeb66616cc87b33a014104edaff8cecd44c7d7843e58c715a0ce213914880ad2b407134f037b30f97af0fc5897fff51cacae39f338d19833f4bd37c8dcf37d31c2651660b3e52ec180995dffffffff0200e1f505000000001976a914e787e5815898ce6b3ba33a6aedf2ca7394a3708c88ac009d7277000000001976a914e576507097443226963dc741cfec7519984104a688ac00000000'
		],
		[
			hex =>
				'0100000001ecfd9e5774d6eb5b5b81c2a793f42883401290b8d17069b4964f7548435ffee4000000008b483045022100906c00fdc404a6547e2440b5830f7921f19d74931ff3d29a72513c010069fe3902207a379dd44796fc7f320fc3ab234c31e07427c3b425e918d0dee3e4864be2832a0141047ca9c5a2867714fe0ea895e40f8bba7d3de95436bc2b23ad292a38df625bc7cc231775f807c98822ef63d50184454977ad5f063cfd985a5c2c69eed49360b27effffffff02001bb700000000001976a914e4a57ff490e66d51e27aa92da68cda84da8039dc88ac80969800000000001976a91428c6e150dbd084d1b9292844e3807483ed38d6ea88ac00000000'
		],
		[
			hex =>
				'0100000001483f790032f0128c03d4655884b1206afc26c1ae7f21e57628a5fb69fd8b8789000000008a473044022017f5119f3e86846b5791c4922a92c99a72ff0db9c459befff4e650151c223d8302207b7301e95cc9f642508679a6e1538a3e4ffadc87e67e8401167098517abce5600141045ca7b90fdb45f711f6badcc3d59b3b68c5328fc99ce9d17747939188f19ec55724d64e6a2fb12bbccbd7414517e3d622665f6c48cb8fb0a063cdcec82f1d6a96ffffffff0140420f00000000001976a9141a63b9abce33453ff15dc58070021d5ff978111a88ac00000000'
		],
		[
			hex =>
				'010000000120017d0c5c91dddce2fd96fad5aab58fc3900b995f290bc60d55d18bad3c761d010000008c493046022100d5250e0e8861678b61560b50ddbbced3f43a91b9b320acdd3c1968e632e67511022100bfd3e5bfbd07c2da16ad0f1ce7d4a5d8ace964a34497234119fe2a56b5e9ca52014104ec229a3115c351abd5ae6141e6ffe628ca0218aaec0d9df5c5915fa5a8a796c2b35dae10adacc61e613006654d7538749e1b585dedb11cfe6b909080963d1691ffffffff02001f1c74000000001976a9140538b4326833aaa3393c45dd39e8881510d9c7ec88ac007e5603000000001976a91456f000ac3ee604a7c2dabd4e82f16d363dcd298288ac00000000'
		],
		[
			hex =>
				'0100000001a1df952936ada0fcd40534024c9ee13c873772fd5423c54de00cbfe48df62cbc000000008b48304502202de8fb6928309adcb760e50b98e8bbe94fb7a30b37f6c0d05d982cab92d1d559022100ac990704bb6b9d1ac5919b2f0b16512f79f3a5e42aca889a8604a8612218bd850141049cb428a3de469ea25ba8539372c5fdb9374187037a659e1f19e1759f2ef3f203bdbd4e04315d9096051dd4cfccd8b15c9433b9eb44af777aa2762a9bb6ff299fffffffff0280841e00000000001976a9144a69eedbdffb72cceb3a982d8856a39c8a32f0f388ac80969800000000001976a914d5dc1f4d24658896095b777b4f57d9eaab3d1bbe88ac00000000'
		],
		[
			hex =>
				'0100000001c0bac00adb3233f62d0e3e2b738c8d7db6171a36287757d0cb7af6e690944025000000008b483045022100f22c7db7979f5c83f20e40d1f312f6cd7675f129e31c143d7d6b53150d25ef1c02202268568cf3a4db98bbf52115f7a77ff39e8368c95a71a7e2df343e65ccb06a87014104ca5a5752bbb7dd3f63a6f1c6c5f04c9e4bb3e0e25397c5a17e0cee94b8e00b05849ee5f5886b8b1c83754cfe287ba18eb68192da7aac245ad685a1e9e4d51dc1ffffffff02c082aa71000000001976a9143c9265037d5a019b77463bf54efed36a51acf68288ac409c7102000000001976a914b55dd29fed068ccc1bc17312559953f6583ee7e488ac00000000'
		],
		[
			hex =>
				'0100000001ac54517fde3f7fac38a8b98e1ddba95cc19a3386eff319983f1e11dd6419fc77000000008a473044022072f14ec0146ac2ae5cfd27de01eaedd28fa50333f25e7eeb83e5b469bc659505022068e0e4edc90b34f0724316358b78d2f08fc6bfb24eba4ca04d98bbdc9628659001410485735457dee46e18cce552fe23369ab9ba8a2a92698bb8b11ae475a7ba97ca96ad25427ad086cb3ad982fda53a96d0cd64b1d8527fecfebe6015e85c8cbbd901ffffffff0180841e00000000001976a9147c6a9535b702c784f0712f0bfe91b25238e1474a88ac00000000'
		],
		[
			hex =>
				'01000000011b202675021f2e2e6ad6d58c5f9afc6be84ddc40de325b03cf93ff59a47e6b54000000008c49304602210086d17054e7748d3c9839183a758fd61b04b2fc70510c824323fd9146cae57913022100c79d0bfc24a52f1ad1db743d3f11bbbb86c2b1382fb84c3a2d64512eb1587b0001410494b0506b05e22e8bcf6ee34d48ca9f2a85dc9353a1007d37223647d2331d8e74c64094715b2bdb98f2ae40ee8e4e009cb4f09dbbe8a3d4176c4b999b687571d0ffffffff028001f06f000000001976a914bd37dc9516767ad1b4164b7441ae5bcfa55d592488ac4081ba01000000001976a914605e62db0e9dcc421f1b5936f5b7c4dfff7a748288ac00000000'
		],
		[
			hex =>
				'0100000001fc3365a14eada2e06a119550e5aaea6b3b3a2aae43c2a436fe0e393b26d518d8000000008b48304502201e40ae899cd6366bb1ab48665d8d24180ba54d744a7c10d6640d3aea6529054e022100c6e9961284f2ab912f22205eca44741b6310f10a0be03d6ab54c281bc7983145014104365c2e2f61e55953e63776c70a179d57dc8a8e53787c6cb95d80c26837c0cdd4b609ff0c83f6efb0076fac00655ace0c177b3c61a1b5e9e77091a0e1739c5c9effffffff02c0f35e01000000001976a914417d48fe8e9bb1971c4a0e21c387a41ae200630488acc00d916e000000001976a9145c9f672855ed4b1adf86a028258323756b78594a88ac00000000'
		],
		[
			hex =>
				'010000000109dcdf98ba6e5323722c594c0edb3a000b6f3da06cf86355f1ada3860306ead7010000008b48304502206cbef8d00d7825f5f5a3c69359d469e6ccb0fa17fcd22572185b6de9c1e45899022100cf3fabdc877088b620b081dc3e43b8533f7473340a8379e25fecced2cff287d5014104f29839480ff1845cc409069f05b9b9fd26e77b1614171b77232e72cc074e5cbe1200796bee5aa20046c711ff59fa8711d9117da5ad13ff14363601f28bb73215ffffffff0280969800000000001976a914795c679389d97af7ee450f1237bd8944d03b4bff88ac4077f86d000000001976a914ec9ec31e2204090c217d9e5ce92afc053cc9b4bd88ac00000000'
		],
		[
			hex =>
				'0100000001c8eb0d3b5cae21773359946538bb3fba6c26bb8264ad29a1023681d8990e381e010000008c493046022100d282841be8911a7355603c5e9154dd221251b1cc247fbdeebcb08b0d3788085e022100fff523f28c7f8b030430a6fc6308d0bcbe1bd5c4434770900f3690ddc914e5a70141045871dcb5a04fc55a657a8dc1095008f1c120d106a499e6c9e29f497b40cc943e937be08bdb0134fa5675aeb81997f380799c0ce23e4ba2ff5fd286e9a9effc2bffffffff02c0cf6a00000000001976a91434931d97bd14e58d50b42e8f10d082649a55ccd088ac80a78d6d000000001976a91462b43150c6f3ec7ccb7966a43aab4be3f79189c988ac00000000'
		],
	];

	is to_format [hex => scalar reverse merkle_root($block_100022)],
		'e05048a9b8e622bda048691a47fd9de332dc1d4b6b9d289d4e12c6722076c4e7', 'block 100022 root ok';
};

subtest 'testing tagged_hash' => sub {
	my $data = pack 'u', 'packed data...';
	my $tag = 'ąść';

	#is(tagged_hash($data, $tag), sha256(sha256(encode 'UTF-8', $tag) . sha256(encode 'UTF-8', $tag) . $data), 'tagged_hash ok');
	is(
		tagged_hash($data, $tag),
		sha256(sha256(encode 'UTF-8', $tag) . sha256(encode 'UTF-8', $tag) . $data),
		'tagged_hash ok'
	);
};

done_testing;

