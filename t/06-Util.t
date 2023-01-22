use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);

use Bitcoin::Crypto::Helpers;    # loads Math::BigInt
use Bitcoin::Crypto::Key::ExtPrivate;
use utf8;

BEGIN {
	use_ok(
		'Bitcoin::Crypto::Util', qw(
			validate_wif
			get_path_info
			generate_mnemonic
			mnemonic_from_entropy
			mnemonic_to_seed
			hash160
			hash256
		)
	);
}

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
			lives_and {
				is(validate_wif($to_test), $result)
			} 'wif validation ok';
		}
		else {
			throws_ok {
				validate_wif($to_test);
			} 'Bitcoin::Crypto::Exception', 'wif validation failed as expected';
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
		is_deeply(get_path_info($case->[0]), $case->[1], "test case $case->[0]");
	}
};

subtest 'testing hash160 / hash256' => sub {
	my $data = pack 'u', 'packed data...';
	is(hash160($data), ripemd160(sha256($data)), 'hash160 ok');
	is(hash256($data), sha256(sha256($data)), 'hash256 ok');
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
			lives_ok {
				Bitcoin::Crypto::Key::ExtPrivate->from_mnemonic($mnemonic, '', 'en');
			} 'generated mnemonic can be imported';
		}
	}

	throws_ok {
		my $mnemonic = generate_mnemonic(129, 'en');
	} 'Bitcoin::Crypto::Exception::MnemonicGenerate', 'invalid entropy dies';

	throws_ok {
		my $mnemonic = mnemonic_from_entropy("\x01" x 17, 'en');
	} 'Bitcoin::Crypto::Exception::MnemonicGenerate', 'invalid entropy dies';
};

done_testing;

