use Test2::V0;
use Bitcoin::Crypto::Helpers qw(pad_hex ensure_length make_strict_der_signature);

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

	ok dies {
		ensure_length pack('x5'), 4;
	}, 'packed data that was too long failed as expected';
};

subtest 'testing make_strict_der_signature' => sub {
	my $strict_sig;

	$strict_sig = make_strict_der_signature(pack 'H*', '3006020100020101');
	is unpack('H*', $strict_sig), '30050200020101', 'strict signature with zero r ok';

	$strict_sig = make_strict_der_signature(pack 'H*', '3006020101020100');
	is unpack('H*', $strict_sig), '30050201010200', 'strict signature with zero s ok';
};

done_testing;

