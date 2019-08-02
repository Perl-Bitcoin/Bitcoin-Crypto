use strict;
use warnings;

use Test::More tests => 6;
use Try::Tiny;
use Math::BigInt;

BEGIN { use_ok('Bitcoin::Crypto::Helpers', qw(pad_hex ensure_length)) };

# pack_hex - 2 tests

my @hexes = qw(1a3efb 1a3ef);

for my $hex (@hexes) {
	my $from_bi = substr Math::BigInt->from_hex("0x$hex")->as_hex(), -length $hex;
	my $from_pack = substr unpack("H*", pack("H*", pad_hex($hex))), -length $hex;
	is($from_pack, $from_bi, "hex packing ok");
}

is(ensure_length(pack("x4"), 4), pack("x4"), "ensuring length does not change data for equal length");
is(ensure_length(pack("x30"), 32), pack("x32"), "ensuring length adds missing zero bytes");
try {
	ensure_length pack("x5"), 4;
	fail("packed data was too long and should've had failed");
} catch {
	pass("packed data that was too long failed as expected");
};