# HARNESS-DURATION-MEDIUM

use Test2::V0;
use Encode qw(encode);
use Bitcoin::Crypto qw(btc_prv);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Util qw(to_format);

# silence warnings
local $SIG{__WARN__} = sub { };

my @cases = (
	{
		priv => '641ce7ab9a2ec7697f32d3ade425d9785e8f23bea3501524852cda3ca05fae28',
		pub =>
			'04394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967c52ad62fe0b27e5acc0992fc8509e5041a06064ce967200b0b7288a4ab889bf22',
	},
	{
		priv => 'b7331fd4ff8c53d31fa7d1625df7de451e55dc53337db64bee3efadb7fdd28d9',
		pub =>
			'043992aa3f9deda22c02d05ca01a55d8f717d7464bb11ef43b59fc36c32613d0205f34f4ef398da815711d8917b804d429f395af403d52cd4b65b76839c88da442',
	},
);

my $case_num = 0;
for my $case (@cases) {
	subtest "should convert private to public, case $case_num" => sub {
		my $privkey = btc_prv->from_serialized([hex => $case->{priv}])->set_compressed(0);

		is(to_format [hex => $privkey->to_serialized], $case->{priv}, 'imported and exported correctly');
		is(
			to_format [hex => $privkey->get_public_key->to_serialized], $case->{pub},
			'correctly created public key'
		);
	};

	++$case_num;
}

my $privkey = btc_prv->from_serialized([hex => $cases[0]{priv}])->set_compressed(0);
my $pubkey = $privkey->get_public_key;
my @messages = ('Perl test script', '', 'a', "_ś\x1f " x 250);

$case_num = 0;
foreach my $message (@messages) {
	subtest "should sign messages, case $case_num" => sub {
		$message = encode('UTF-8', $message);
		my $signature = $privkey->sign_message($message);

		ok($privkey->verify_message($message, $signature), 'Valid signature');
		ok($pubkey->verify_message($message, $signature), 'Pubkey recognizes signature');

		my $privkey2 = btc_prv->from_serialized([hex => $cases[1]{priv}]);
		my $pubkey2 = $privkey2->get_public_key;

		ok(
			!$pubkey2->verify_message($message, $signature),
			'Different pubkey does not recognize signature'
		);
	};

	++$case_num;
}

subtest 'should import and export WIF' => sub {
	my $wif_raw_key = '972e85e7e3345cb7e6a5f812aa5f5bea82005e3ded7b32d9d56f5ab2504f1648';
	my $wif = '5JxsKGzCoJwaWEjQvfNqD4qPEoUQ696BUEq68Y68WQ2GNR6zrxW';
	my $testnet_wif = '92jVu1okPY1iUJEhZ1Gk5fPLtTq7FJdNpBh3DASdr8mK9SZXqy3';
	is(to_format [hex => btc_prv->from_wif($wif)->to_serialized], $wif_raw_key, 'imported WIF correctly');
	is(
		btc_prv->from_serialized([hex => $wif_raw_key])->set_compressed(0)->to_wif, $wif,
		'exported WIF correctly'
	);
	is(
		btc_prv->from_wif($testnet_wif)->network->name,
		'Bitcoin Testnet',
		'Recognized non-default network'
	);
	is(
		to_format [hex => btc_prv->from_wif($testnet_wif)->to_serialized],
		$wif_raw_key, 'imported non-default network WIF correctly'
	);
	is(
		btc_prv->from_wif($testnet_wif)->get_public_key->network->name,
		'Bitcoin Testnet',
		'Passed network to public key'
	);
};

subtest 'should validate key length' => sub {
	my $short_key = 'e8d964843cc55a91d';
	my $longer_key = 'd0a08067d186ffd9d14e8d964843cc55a91d';
	my $too_long_key = 'a3bc641ce7ab9a2ec7697f32d3ade425d9785e8f23bea3501524852cda3ca05fae28';

	is(
		length btc_prv->from_serialized([hex => $short_key])->to_serialized,
		Bitcoin::Crypto::Constants::key_max_length, 'Short key length OK'
	);
	is(
		length btc_prv->from_serialized([hex => $longer_key])->to_serialized,
		Bitcoin::Crypto::Constants::key_max_length, 'Longer key length OK'
	);

	isa_ok dies {
		btc_prv->from_serialized([hex => $too_long_key]);
	}, 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'should not allow creation of private keys from public key data' => sub {
	isa_ok dies {
		btc_prv->from_serialized([hex => $cases[0]{pub}]);
	}, 'Bitcoin::Crypto::Exception::KeyCreate';
};

done_testing;

