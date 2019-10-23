use strict;
use warnings;

use Test::More;
use Try::Tiny;
use Scalar::Util qw(blessed);

BEGIN { use_ok('Bitcoin::Crypto::Bech32', qw(:all)) };

# silence warnings
local $SIG{__WARN__} = sub {};

my %tests = (
	"A12UEL5L" => {
		type => "bech32",
		data => ""
	},
	"a12uel5l" => {
		type => "bech32",
		data => ""
	},
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs" => {
		type => "bech32",
		data => ""
	},
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw" => {
		type => "bech32",
		data => "00443214c74254b635cf84653a56d7c675be77df"
	},
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j" => {
		type => "bech32",
		data => "00" x 51
	},
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w" => {
		type => "bech32",
		data => "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d"
	},
	"?1ezyfcl" => {
		type => "bech32",
		data => ""
	},
	"\x201nwldj5" => {
		type => "bech32",
		exception => "bech32_input_format"
	}, # Invalid character in HRP
	"\x7f1axkwrx" => {
		type => "bech32",
		exception => "bech32_input_format"
	}, # Invalid character in HRP
	"\x801eym55h" => {
		type => "bech32",
		exception => "bech32_input_format"
	}, # Invalid character in HRP
	"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx" => {
		type => "bech32",
		exception => "bech32_input_format"
	},
	"pzry9x0s0muk" => {
		type => "bech32",
		exception => "bech32_input_format"
	},
	"1pzry9x0s0muk" => {
		type => "bech32",
		exception => "bech32_input_format"
	},
	"x1b4n0q5v" => {
		type => "bech32",
		exception => "bech32_input_format"
	},
	"li1dgmt3" => {
		type => "bech32",
		exception => "bech32_input_format"
	}, # Too short data part
	"de1lg7wt\xff" => {
		type => "bech32",
		exception => "bech32_input_format"
	}, # Invalid character in data part
	"A1G7SGD8" => {
		type => "bech32",
		exception => "bech32_input_checksum"
	}, # Invalid checksum
	"10a06t8" => {
		type => "bech32",
		exception => "bech32_input_format"
	}, # Empty HRP
	"1qzzfhee" => {
		type => "bech32",
		exception => "bech32_input_format"
	}, # Empty HRP
	"checksum1qazjduhr" => {
		type => "bech32",
		exception => "bech32_input_checksum"
	}, # Invalid checksum

	# SEGREGATED WITNESS
	"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" => {
		type => "segwit",
		data => "00751e76e8199196d454941c45d1b3a323f1433bd6"
	},
	"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx" => {
		type => "segwit",
		data => "01751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"
	},
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" => {
		type => "segwit",
		data => "001863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
	},
	"BC1SW50QA3JX3S" => {
		type => "segwit",
		data => "10751e"
	},
	"bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj" => {
		type => "segwit",
		data => "02751e76e8199196d454941c45d1b3a323"
	},
	"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" => {
		type => "segwit",
		data => "00000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
	},
	"bc1qtxl7x889mkneu8fum3q0645eph4fctewa83trd" => {
		type => "segwit",
		data => "0059bfe31ce5dda79e1d3cdc40fd56990dea9c2f2e",
	},
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7" => {
		type => "segwit",
		exception => "bech32_input_format"
	},
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5" => {
		type => "segwit",
		exception => "bech32_input_checksum"
	},
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5" => {
		type => "segwit",
		exception => "bech32_input_checksum"
	}, # Invalid checksum
	"BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2" => {
		type => "segwit",
		exception => "segwit_program"
	}, # Invalid witness version
	"bc1rw5uspcuh" => {
		type => "segwit",
		exception => "segwit_program"
	}, # Invalid program length
	"bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90" => {
		type => "segwit",
		exception => "segwit_program"
	}, # Invalid program length
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7" => {
		type => "segwit",
		exception => "bech32_input_format"
	}, # Mixed case
	"bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du" => {
		type => "segwit",
		exception => "bech32_input_data"
	}, # zero padding of more than 4 bits
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv" => {
		type => "segwit",
		exception => "bech32_input_data"
	}, # Non-zero padding in 8-to-5 conversion
	"bc1gmk9yu" => {
		type => "segwit",
		exception => "segwit_program"
	}, # Empty data section
);

while (my ($test, $tdata) = each %tests) {
	my ($encoder, $decoder);
	if ($tdata->{type} eq "segwit") {
		$encoder = \&encode_segwit;
		$decoder = \&decode_segwit;
	} elsif ($tdata->{type} eq "bech32") {
		$encoder = \&encode_bech32;
		$decoder = \&decode_bech32;
	}

	try {
		my ($hrp, $data) = split_bech32($test);
		if (defined $tdata->{data}) {
			my $result = $tdata->{data};
			is(unpack("H*", $decoder->($test)), $result, "$tdata->{type} decode result ok");
			is($encoder->($hrp, pack "H*", $result), lc $test, "$tdata->{type} encoding ok");
		} elsif (defined $tdata->{exception}) {
			$decoder->($test);
			fail("decoding should've failed but didn't: $test");
		}
	} catch {
		my $err = $_;
		if (blessed $err && $err->isa("Bitcoin::Crypto::Exception")) {
			if (defined $tdata->{exception}) {
				is($err->code, $tdata->{exception}, "$tdata->{type} error code ok: " . $err->message);
			} else {
				fail("unexpected error: `$err`, $test");
			}
		} else {
			fail("unknown error `$err`: $test");
		}
	};
}

done_testing;
