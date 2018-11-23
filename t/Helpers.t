use strict;
use warnings;

use Test::More tests => 3;
use Math::BigInt;

BEGIN { use_ok('Bitcoin::Crypto::Helpers', qw(pad_hex)) };

# pack_hex - 2 tests

my @hexes = qw(1a3efb 1a3ef);

for my $hex (@hexes) {
    my $from_bi = substr Math::BigInt->from_hex("0x$hex")->as_hex(), -length $hex;
    my $from_pack = substr unpack("H*", pack("H*", pad_hex($hex))), -length $hex;
    is($from_pack, $from_bi, "hex packing ok");
}
