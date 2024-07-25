use Test2::V0;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);

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

done_testing;

