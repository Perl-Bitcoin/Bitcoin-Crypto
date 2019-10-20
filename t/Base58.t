use strict;
use warnings;

use Test::More;
use Try::Tiny;
use Digest::SHA qw(sha256);
use Scalar::Util qw(blessed);

BEGIN { use_ok('Bitcoin::Crypto::Base58', qw(:all)) };

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
);

my @cases_error = (
	[
		"oa4.#1Q9",
		"base58_input_format",
	],
	[
		"oa4Az1Q9",
		"base58_input_checksum",
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
	try {
		decode_base58check($case->[0]);
		fail("invalid data pass silently");
	} catch {
		my $ex = $_;
		pass("invalid data raises an exception")
			if blessed $ex && $ex->isa("Bitcoin::Crypto::Exception") && $ex->code eq $case->[1];
	};
}

done_testing;
