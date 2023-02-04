use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN {
	use_ok(
		'Bitcoin::Crypto::Helpers',
		qw(pad_hex ensure_length pack_varint unpack_varint)
	);
}

subtest 'testing pad_hex' => sub {
	my @hexes = qw(1a3efb 1a3ef 0);

	for my $hex (@hexes) {
		my $from_bi = substr Math::BigInt->from_hex("0x$hex")->as_hex(), -length $hex;
		my $from_pack = substr unpack('H*', pack('H*', pad_hex($hex))), -length $hex;
		is($from_pack, $from_bi, 'hex packing ok');
	}
};

subtest 'testing ensure_length' => sub {
	is(
		ensure_length(pack('x4'), 4),
		pack('x4'), 'ensuring length does not change data for equal length'
	);
	is(ensure_length(pack('x30'), 32), pack('x32'), 'ensuring length adds missing zero bytes');
	dies_ok {
		ensure_length pack('x5'), 4;
	} 'packed data that was too long failed as expected';
};

subtest 'testing varint one byte' => sub {
	is pack_varint(128), "\x80", 'packing ok';
	is unpack_varint("\x80"), 128, 'unpacking ok';
};

subtest 'testing varint one byte (high)' => sub {
	is pack_varint(255), "\xfd\xff\x00", 'packing ok';
	is unpack_varint("\xfd\xff\x00"), 255, 'unpacking ok';
};

subtest 'testing varint two bytes' => sub {
	is pack_varint(515), "\xfd\x03\x02", 'packing ok';
	is unpack_varint("\xfd\x03\x02"), 515, 'unpacking ok';
};

subtest 'testing varint four bytes' => sub {
	is pack_varint(75105), "\xfe\x61\x25\x01\x00", 'packing ok';
	is unpack_varint("\xfe\x61\x25\x01\x00"), 75105, 'unpacking ok';
};


done_testing;

