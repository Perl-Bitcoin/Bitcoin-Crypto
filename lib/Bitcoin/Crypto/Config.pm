package Bitcoin::Crypto::Config;

use v5.10;
use strict;
use warnings;

use Config;

use constant {
	curve_name => 'secp256k1',
	max_child_keys => (2 << 30),
	key_max_length => 32,
	wif_compressed_byte => "\x01",
	compress_public_point => 1,
	segwit_witness_version => 0,
	taproot_witness_version => 1,
	max_witness_version => 16,
};

use constant {
	ivsize => $Config{ivsize},
	is_32bit => $Config{ivsize} == 4,
	is_64bit => $Config{ivsize} >= 8,
};

1;

# Internal use only

