use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(:all);
use Bitcoin::Crypto::Base58 qw(:all);
use Bitcoin::Crypto::Bech32 qw(:all);
use Bitcoin::Crypto::Util qw(generate_mnemonic);

subtest 'testing invalid hex' => sub {
	throws_ok {
		btc_pub->from_hex('not-a-hex');
	} 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'testing undef as a bytestring' => sub {
	throws_ok {
		btc_pub->from_bytes(undef);
	} qr/not a bytestring/;
};

subtest 'testing empty string as a bytestring' => sub {
	throws_ok {
		btc_pub->from_bytes('');
	} 'Bitcoin::Crypto::Exception::KeyCreate';
};

subtest 'testing reference as a bytestring' => sub {
	throws_ok {
		btc_pub->from_bytes(['11']);
	} qr/not a bytestring/;
};

subtest 'testing invalid verification algorithm' => sub {
	my $master_key = btc_extprv->from_mnemonic(generate_mnemonic);
	my $private_key = $master_key->get_basic_key;
	my $public_key = $private_key->get_public_key;

	throws_ok {
		$public_key->verify_message('message', "\x00", 'not-a-hashing-algo');
	} 'Bitcoin::Crypto::Exception::Verify';
};

subtest 'testing invalid base58' => sub {
	throws_ok {
		decode_base58('158ZaF+');
	} 'Bitcoin::Crypto::Exception::Base58InputFormat';
};

subtest 'testing invalid bech32' => sub {
	throws_ok {
		decode_bech32('bc1+-aaa');
	} 'Bitcoin::Crypto::Exception::Bech32InputFormat';
};

done_testing;

