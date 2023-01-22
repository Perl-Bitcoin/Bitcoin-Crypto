use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(:all);
use Bitcoin::Crypto::Base58 qw(:all);
use Bitcoin::Crypto::Bech32 qw(:all);
use Bitcoin::Crypto::Util qw(generate_mnemonic);

throws_ok sub {
	btc_pub->from_hex('not-a-hex');
	},
	'Bitcoin::Crypto::Exception::KeyCreate',
	'invalid hex ok';

throws_ok sub {
	btc_pub->from_bytes(undef);
	},
	'Bitcoin::Crypto::Exception',
	'invalid bytestring (undef) ok';

throws_ok sub {
	btc_pub->from_bytes('');
	},
	'Bitcoin::Crypto::Exception::KeyCreate',
	'invalid bytestring (empty string) ok';

throws_ok sub {
	btc_pub->from_bytes(['11']);
	},
	'Bitcoin::Crypto::Exception',
	'invalid bytestring (reference) ok';

my $master_key = btc_extprv->from_mnemonic(generate_mnemonic);
my $private_key = $master_key->get_basic_key;
my $public_key = $private_key->get_public_key;

throws_ok sub {
	$public_key->verify_message('message', "\x00", 'not-a-hashing-algo');
	},
	'Bitcoin::Crypto::Exception::Verify',
	'invalid algo ok';

throws_ok sub {
	decode_base58(\0);
	},
	'Bitcoin::Crypto::Exception::Base58InputFormat',
	'base58 reference ok';

throws_ok sub {
	decode_bech32(undef);
	},
	'Bitcoin::Crypto::Exception::Bech32InputFormat',
	'bech32 undef ok';

done_testing;

