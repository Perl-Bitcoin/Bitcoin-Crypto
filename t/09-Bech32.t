use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok('Bitcoin::Crypto::Bech32', qw(:all)) }

# BECH32 / BECH32M
my @tests_bech32 = (
	{
		case => 'A12UEL5L',
		type => 'bech32',
		data => []
	},

	{
		case => 'a12uel5l',
		type => 'bech32',
		data => []
	},

	{
		case => 'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
		type => 'bech32',
		data => []
	},

	{
		case => 'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
		type => 'bech32',
		data => [
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
		]
	},

	{
		case => '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
		type => 'bech32',
		data => [(0) x 82]
	},

	{
		case => 'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
		type => 'bech32',
		data => [
			24, 23, 25, 24, 22, 28, 1, 16, 11, 29, 8, 25, 23, 29, 19, 13, 16, 23, 29, 22, 25, 28, 1, 16,
			11, 3, 25, 29, 27, 25, 3, 3, 29, 19, 11, 25, 3, 3, 25, 13, 24, 29, 1, 25, 3, 3, 25, 13
		]
	},

	{
		case => '?1ezyfcl',
		type => 'bech32',
		data => []
	},

	{
		case => 'asd1nyvqgdr08nh7p9r4kwjtrgjt685c7wggd8fhr3gtap3sasj0egcs500w9e',
		type => 'bech32',
		data => [
			19, 4, 12, 0, 8, 13, 3, 15, 7, 19, 23, 30, 1, 5, 3, 21, 22, 14,
			18, 11, 3, 8, 18, 11, 26, 7, 20, 24, 30, 14, 8, 8, 13, 7, 9, 23,
			3, 17, 8, 11, 29, 1, 17, 16, 29, 16, 18, 15, 25, 8, 24, 16
		]
	},

	{
		case => 'qq1rgyr56nk7ag7kyyfr4y3ec2vt98qh6h9l46e45thq6spgw6gr5k5gzs0v90mv',
		type => 'bech32',
		data => [
			3, 8, 4, 3, 20, 26, 19, 22, 30, 29, 8, 30, 22, 4, 4, 9, 3, 21, 4, 17,
			25, 24, 10, 12, 11, 5, 7, 0, 23, 26, 23, 5, 31, 21, 26, 25, 21, 20, 11, 23,
			0, 26, 16, 1, 8, 14, 26, 8, 3, 20, 22, 20, 8, 2, 16
		]
	},

	{
		case => 'A1LQFN3A',
		type => 'bech32m',
		data => []
	},

	{
		case => 'a1lqfn3a',
		type => 'bech32m',
		data => []
	},

	{
		case => 'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
		type => 'bech32m',
		data => []
	},

	{
		case => 'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
		type => 'bech32m',
		data => [
			31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
		]
	},

	{
		case => '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
		type => 'bech32m',
		data => [(31) x 82]
	},

	{
		case => 'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
		type => 'bech32m',
		data => [
			24, 23, 25, 24, 22, 28, 1, 16, 11, 29, 8, 25, 23, 29, 19, 13, 16, 23, 29, 22, 25, 28, 1, 16,
			11, 3, 25, 29, 27, 25, 3, 3, 29, 19, 11, 25, 3, 3, 25, 13, 24, 29, 1, 25, 3, 3, 25, 13
		]
	},

	{
		case => '?1v759aa',
		type => 'bech32m',
		data => []
	},

	# negative tests
	{
		case => "\x201nwldj5",
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},    # Invalid character in HRP

	{
		case => "\x7f1axkwrx",
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},    # Invalid character in HRP

	{
		case => "\x801eym55h",
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},    # Invalid character in HRP

	{
		case => 'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx',
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},

	{
		case => 'pzry9x0s0muk',
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},

	{
		case => '1pzry9x0s0muk',
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},

	{
		case => 'x1b4n0q5v',
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},

	{
		case => 'li1dgmt3',
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},    # Too short data part

	{
		case => "de1lg7wt\xff",
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},    # Invalid character in data part

	{
		case => 'A1G7SGD8',
		type => 'bech32',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => '10a06t8',
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},    # Empty HRP

	{
		case => '1qzzfhee',
		type => 'bech32',
		exception => 'Bech32InputFormat'
	},    # Empty HRP

	{
		case => 'checksum1qazjduhr',
		type => 'bech32',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4',
		type => 'bech32m',
		exception => 'Bech32InputFormat'
	},

	{
		case => 'M1VUXWEZ',
		type => 'bech32m',
		exception => 'Bech32InputChecksum'
	},    # checksum calculated with uppercase form of HRP
);

# SEGREGATED WITNESS
# From SegWit BIP test vectors, we must change the first byte if the segwit version is greater than 0
# (version 1 = 0x51)
# And strip the 0x20 that follows it.
# This is done because the vectors present the scriptPubKey, which has script opcodes in it
# (0x20 = push 20 bytes, OP_1 = 0x51)
my @tests_segwit = (
	{
		case => 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
		data => '00751e76e8199196d454941c45d1b3a323f1433bd6'
	},
	{
		case => 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
		data => '001863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'
	},
	{
		case => 'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
		data => '00000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'
	},
	{
		case => 'bc1qtxl7x889mkneu8fum3q0645eph4fctewa83trd',
		data => '0059bfe31ce5dda79e1d3cdc40fd56990dea9c2f2e',
	},
	{
		case => 'bc1qcx0yh6nduwvjua9aq5ks296pkn8ddx585kdqnu',
		data => '00c19e4bea6de3992e74bd052d051741b4ced69a87',
	},

	{
		case => 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y',
		data => '01751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'
	},

	{
		case => 'BC1SW50QGDZ25J',
		data => '10751e'
	},

	{
		case => 'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs',
		data => '02751e76e8199196d454941c45d1b3a323'
	},

	{
		case => 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c',
		data => '01000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'
	},

	{
		case => 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
		data => '0179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	},

	# negative segwit tests
	{
		case => 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
		exception => 'Bech32InputFormat'
	},

	{
		case => 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
		exception => 'SegwitProgram'
	},    # Invalid witness version

	{
		case => 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
		exception => 'SegwitProgram'
	},    # Invalid program length

	{
		case => 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
		exception => 'Bech32InputFormat'
	},    # Mixed case

	{
		case => 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv',
		exception => 'Bech32InputData'
	},    # Non-zero padding in 8-to-5 conversion

	{
		case => 'bc1q9zpgru',
		exception => 'SegwitProgram'
	},    # Empty data section

	{
		case => 'bc1pdg93mv',
		exception => 'SegwitProgram'
	},    # Empty data section

	{
		case => 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum

	{
		case => 'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
		exception => 'Bech32InputFormat'
	},    # Invalid character in checksum

	{
		case => 'BC1SW50QA3JX3S',
		exception => 'Bech32InputChecksum'
	},    # Invalid checksum (bech32 for segwit > 0)

	{
		case => 'bc1pw5dgrnzv',
		exception => 'SegwitProgram'
	},    # Invalid program length

	{
		case => 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
		exception => 'SegwitProgram'
	},    # Invalid program length

	{
		case => 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
		exception => 'Bech32InputData'
	},    # zero padding of more than 4 bits

	{
		case => 'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j',
		exception => 'Bech32InputData'
	},    # Non-zero padding in 8-to-5 conversion
);

for my $test (@tests_bech32) {
	subtest "testing $test->{type} $test->{case}" => sub {
		if (defined $test->{data}) {
			my @result = decode_bech32($test->{case});

			is_deeply $result[1], $test->{data}, 'decode result ok';
			is $result[2], $test->{type}, 'result type ok';
			is encode_bech32(@result), lc $test->{case}, 'encode result ok';
		}
		elsif (defined $test->{exception}) {
			throws_ok {
				decode_bech32($test->{case});
			} 'Bitcoin::Crypto::Exception::' . $test->{exception}, 'decoding fails ok';
		}
	};
}

for my $test (@tests_segwit) {
	subtest 'testing segwit: ' . $test->{case} => sub {
		if (defined $test->{data}) {
			my $result = decode_segwit($test->{case});
			my ($hrp, $data, $type) = decode_bech32($test->{case});

			my $wanted_type = $data->[0] == 0 ? 'bech32' : 'bech32m';
			is $type, $wanted_type, 'valid encoding type';

			is unpack('H*', $result), $test->{data}, 'decode result ok';
			is encode_segwit($hrp, pack 'H*', $test->{data}), lc $test->{case}, 'encode result ok';
		}
		elsif (defined $test->{exception}) {
			throws_ok {
				decode_segwit($test->{case});
			} 'Bitcoin::Crypto::Exception::' . $test->{exception}, 'decoding fails ok';
		}
	};
}

done_testing;

