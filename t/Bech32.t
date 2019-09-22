use strict;
use warnings;

use Test::More tests => 3;

BEGIN { use_ok('Bitcoin::Crypto::Bech32', qw(:all)) };

my $case = pack("H*", "a0bc153fea");

is($case, decode_bech32(encode_bech32($case)),
	"encoding and decoding yields initial value");
ok(!defined decode_bech32(".."), "unknown symbols in decoding returns undef");
