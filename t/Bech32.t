use strict;
use warnings;

use Test::More;
use Try::Tiny;

BEGIN { use_ok('Bitcoin::Crypto::Bech32', qw(:all)) };

my %tests = (
	"A12UEL5L" => "",
	"a12uel5l" => "",
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs" => "",
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw" => pack("H*", "00443214c74254b635cf84653a56d7c675be77df"),
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j" => pack("x82"),
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w" => pack("H*", "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d"),
	"?1ezyfcl" => "",
	chr(0x20) . "1nwldj5" => "bech32_input_format",
	chr(0x7F) . "1axkwrx" => "bech32_input_format",
	chr(0x80) . "1eym55h" => "bech32_input_format",
	"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx" => "bech32_input_format",
	"pzry9x0s0muk" => "bech32_input_format",
	"1pzry9x0s0muk" => "bech32_input_format",
	"x1b4n0q5v" => "bech32_input_format",
	"li1dgmt3" => "bech32_input_format",
	"de1lg7wt" . chr(0xFF) => "bech32_input_format",
	"A1G7SGD8" => "bech32_input_checksum",
	"10a06t8" => "bech32_input_format",
	"1qzzfhee" => "bech32_input_format",
	"checksum1qazjduhr" => "bech32_input_checksum",
);

while (my ($test, $result) = each %tests) {
	try {
		my ($hrp, $data) = split_bech32($test);
		my $decoded = decode_bech32($test);
		is($decoded, $result, "bech32 decode result ok");
		is(encode_bech32($hrp, $decoded), lc $test, "bech32 encoding ok");
	} catch {
		my $err = $_;
		if (ref $err) {
			is($err->{reason}, $result, "error code ok");
		} else {
			fail("unknown error: $err");
		}
	};
}

done_testing();
