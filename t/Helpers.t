use strict;
use warnings;

use Test::More;
use Try::Tiny;
use Math::BigInt;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Digest::SHA qw(sha256);

BEGIN { use_ok('Bitcoin::Crypto::Helpers', qw(pad_hex ensure_length hash160 hash256)) };


my @hexes = qw(1a3efb 1a3ef 0);

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

my $data = pack "u", "packed data...";
is(hash160($data), ripemd160(sha256($data)), "hash160 ok");
is(hash256($data), sha256(sha256($data)), "hash256 ok");

done_testing;
