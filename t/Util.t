use strict;
use warnings;

use Test::More tests => 9;
use Math::BigInt;

BEGIN { use_ok('Bitcoin::Crypto::Util', qw(pack_hex validate_wif validate_address)) };

# pack_hex - 2 tests

my @hexes = qw(1a3efb 1a3ef);

for my $hex (@hexes) {
    my $from_bi = substr Math::BigInt->from_bytes(pack_hex($hex))->as_hex(), -length $hex;
    my $from_pack = substr unpack("H*", pack_hex($hex)), -length $hex;
    is($from_pack, $from_bi, "hex packing ok");
}

# validate_wif - 3 tests

ok(validate_wif("935hpxoy4BGeuHmmtjURq52SehWtRoSArv6mJVZbVXUWyN9HQ5T"), "wif validation ok");
ok(!validate_wif("xyz"), "wif validation ok - invalid wif");
ok(!defined validate_wif("IOU"), "wif validation ok - invalid base58 wif");


# validate_address - 3 tests

ok(validate_address("mpyspBXHGvDMGiV6RpeWeVvSierBhysfdq"), "address validation ok");
ok(!validate_address("xyz"), "address validation ok - invalid address");
ok(!defined validate_wif("IOU"), "address validation ok - invalid base58 address");
