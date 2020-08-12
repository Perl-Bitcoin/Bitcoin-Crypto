use v5.10; use warnings;
use Test::More;
use Test::Exception;
use Bitcoin::Crypto;

BEGIN { use_ok('Bitcoin::Crypto::Bech32', qw(:all)) }

is(Bitcoin::Crypto::Bech32->VERSION, Bitcoin::Crypto->VERSION);

# silence warnings
local $SIG{__WARN__} = sub { };

my %tests = (
	"A12UEL5L" => {
		type => "bech32",
		data => ""
	},
	"a12uel5l" => {
		type => "bech32",
		data => ""
	},
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs" =>
		{
		type => "bech32",
		data => ""
		},
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw" => {
		type => "bech32",
		data => "00443214c74254b635cf84653a56d7c675be77df"
	},
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j" =>
		{
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
	"asd1nyvqgdr08nh7p9r4kwjtrgjt685c7wggd8fhr3gtap3sasj0egcs500w9e" => {
		type => "bech32",
		data => "991804346f3cefe09475b3a4b1a24bd1e98f390869d371c50be8630ec24fca31"
	},
	"qq1rgyr56nk7ag7kyyfr4y3ec2vt98qh6h9l46e45thq6spgw6gr5k5gzs0v90mv" => {
		type => "bech32",
		data => "1a083a6a76f751eb10891d491ce14c594e0beae5fd759ad17706a0143b481d2d440a"
	},
	"\x201nwldj5" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},    # Invalid character in HRP
	"\x7f1axkwrx" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},    # Invalid character in HRP
	"\x801eym55h" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},    # Invalid character in HRP
	"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"
		=> {
		type => "bech32",
		exception => "Bech32InputFormat"
		},
	"pzry9x0s0muk" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},
	"1pzry9x0s0muk" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},
	"x1b4n0q5v" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},
	"li1dgmt3" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},    # Too short data part
	"de1lg7wt\xff" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},    # Invalid character in data part
	"A1G7SGD8" => {
		type => "bech32",
		exception => "Bech32InputChecksum"
	},    # Invalid checksum
	"10a06t8" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},    # Empty HRP
	"1qzzfhee" => {
		type => "bech32",
		exception => "Bech32InputFormat"
	},    # Empty HRP
	"checksum1qazjduhr" => {
		type => "bech32",
		exception => "Bech32InputChecksum"
	},    # Invalid checksum

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
		exception => "Bech32InputFormat"
	},
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5" => {
		type => "segwit",
		exception => "Bech32InputChecksum"
	},
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5" => {
		type => "segwit",
		exception => "Bech32InputChecksum"
	},    # Invalid checksum
	"BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2" => {
		type => "segwit",
		exception => "SegwitProgram"
	},    # Invalid witness version
	"bc1rw5uspcuh" => {
		type => "segwit",
		exception => "SegwitProgram"
	},    # Invalid program length
	"bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90" => {
		type => "segwit",
		exception => "SegwitProgram"
	},    # Invalid program length
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7" => {
		type => "segwit",
		exception => "Bech32InputFormat"
	},    # Mixed case
	"bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du" => {
		type => "segwit",
		exception => "Bech32InputData"
	},    # zero padding of more than 4 bits
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv" => {
		type => "segwit",
		exception => "Bech32InputData"
	},    # Non-zero padding in 8-to-5 conversion
	"bc1gmk9yu" => {
		type => "segwit",
		exception => "SegwitProgram"
	},    # Empty data section
);

while (my ($test, $tdata) = each %tests) {
	my ($encoder, $decoder);
	if ($tdata->{type} eq "segwit") {
		$encoder = \&encode_segwit;
		$decoder = \&decode_segwit;
	}
	elsif ($tdata->{type} eq "bech32") {
		$encoder = \&encode_bech32;
		$decoder = \&decode_bech32;
	}

	if (defined $tdata->{data}) {
		my ($result, $hrp, $data) = $tdata->{data};
		lives_ok {
			($hrp, $data) = split_bech32($test);
		}
		"general validation passed";
		lives_and {
			is(unpack("H*", $decoder->($test)), $result)
		}
		"$tdata->{type} decode result ok";
		lives_and {
			is($encoder->($hrp, pack "H*", $result), lc $test)
		}
		"$tdata->{type} encoding ok";
	}
	elsif (defined $tdata->{exception}) {
		throws_ok {
			my ($hrp, $data) = split_bech32($test);
			$decoder->($test);
		}
		"Bitcoin::Crypto::Exception::" . $tdata->{exception}, "decoding fails";
		note($@->message);
	}
}

done_testing;
