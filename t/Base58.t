use v5.10; use warnings;
use Test::More;
use Test::Exception;
use Bitcoin::Crypto;
use Crypt::Digest::SHA256 qw(sha256);

BEGIN { use_ok('Bitcoin::Crypto::Base58', qw(:all)) };

is(Bitcoin::Crypto::Base58->VERSION, Bitcoin::Crypto->VERSION);

my @cases = (
	[
		"0034578340587230457234085723045DCACC0031AF",
		"15mkyTvdDkFcy6sPBmk9uFzkTk6LKVpWeD",
	],
	[
		"00B14D64E7F6DD291A5649CF7777213BB068B527E4",
		"1HAVKPu8S4MtaLyK7mpFM91ikK6NG2GuXL",
	],
	[
		"0054DB7ABEF5170E52C9E620DD6FE9F1219AC14B2C",
		"18jggpH3C4TLSeiCfTYppsLCs9PJNUncib",
	],
	[
		"0031837307191B86ACAED69D77D8DEB17964BC406A",
		"15WoafE3pwTzrGXARQgJN64ynb9tkyxP8Z",
	],
	[
		"000000AB68E084523974AF22624AD29B18C90C11235436E963",
		"1116FRkHpUdB9CweWruFSXeFrvZ94gD7VVp6ip5",
	]
);

my @cases_error = (
	[
		"oa4.#1Q9",
		"Base58InputFormat",
	],
	[
		"oa4Az1Q9",
		"Base58InputChecksum",
	],
);

foreach my $case (@cases) {
	my $case_packed = pack("H*", $case->[0]);
	is($case_packed, decode_base58check($case->[1]), "valid decoding");
	is($case->[1], encode_base58check($case_packed), "valid encoding");

	my $decoded_with_check = decode_base58_preserve($case->[1]);
	is(substr($decoded_with_check, 0, -4), $case_packed, "base58check value unchanged");
	is(pack("a4", sha256(sha256(substr $decoded_with_check, 0, -4))),
		substr($decoded_with_check, -4),
		"checksum is valid");
}

foreach my $case (@cases_error) {
	throws_ok {
		decode_base58check($case->[0]);
	} "Bitcoin::Crypto::Exception::" . $case->[1], "invalid data raises an exception";
}

done_testing;
