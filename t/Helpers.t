use v5.10; use warnings;
use Test::More;
use Test::Exception;
use Math::BigInt;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);

BEGIN { use_ok('Bitcoin::Crypto::Helpers', qw(new_bigint pad_hex ensure_length verify_bytestring hash160 hash256)) }

my @bytes = ("\x00\x11", "\x01", "\xff" x 21, "\x00");

for my $case (@bytes) {
	my $from_bi = Math::BigInt->from_bytes($case);
	my $from_helpers = new_bigint($case);
	is($from_helpers, $from_bi, "BigInt construction ok");
}

my @hexes = qw(1a3efb 1a3ef 0);

for my $hex (@hexes) {
	my $from_bi = substr Math::BigInt->from_hex("0x$hex")->as_hex(), -length $hex;
	my $from_pack = substr unpack("H*", pack("H*", pad_hex($hex))), -length $hex;
	is($from_pack, $from_bi, "hex packing ok");
}

is(
	ensure_length(pack("x4"), 4),
	pack("x4"), "ensuring length does not change data for equal length"
);
is(ensure_length(pack("x30"), 32), pack("x32"), "ensuring length adds missing zero bytes");
dies_ok {
	ensure_length pack("x5"), 4;
}
"packed data that was too long failed as expected";

my $data = pack "u", "packed data...";
is(hash160($data), ripemd160(sha256($data)), "hash160 ok");
is(hash256($data), sha256(sha256($data)), "hash256 ok");

lives_ok {
	verify_bytestring(join "", map chr, 0 .. 255);
} "byte string check ok";

dies_ok {
	verify_bytesting(chr(255) . chr (256));
} "byte string check ok";
done_testing;
