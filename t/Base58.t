use strict;
use warnings;

use Test::More tests => 6;
use Try::Tiny;
use Digest::SHA qw(sha256);

BEGIN { use_ok('Bitcoin::Crypto::Base58', qw(:all)) };

my $case = pack("H*", "0000a0bc153fea");

# default base58
is($case, decode_base58_preserve(encode_base58_preserve($case)),
    "encoding and decoding yields initial value");
like(encode_base58_preserve($case), qr/^11/, "perserving zeros works");
ok(!defined decode_base58(".."), "unknown symbols in decoding returns undef");

my $with_check = encode_base58check($case);
my $decoded_with_check = decode_base58_preserve($with_check);

# base58check

is(substr($decoded_with_check, 0, -4), $case, "base58check value unchanged");
is(pack("a4", sha256(sha256(substr $decoded_with_check, 0, -4))),
    substr($decoded_with_check, -4),
    "checksum is valid");

