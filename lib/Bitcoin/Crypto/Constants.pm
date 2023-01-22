package Bitcoin::Crypto::Constants;

use v5.10;
use strict;
use warnings;

use Config;

# These constants are used generally safe to use outside Bitcoin::Crypto code
# if you need them
use constant {
	curve_name => 'secp256k1',
	max_child_keys => (2 << 30),
	key_max_length => 32,
	wif_compressed_byte => "\x01",
	segwit_witness_version => 0,
	taproot_witness_version => 1,
	max_witness_version => 16,

	bip44_legacy_purpose => 44,
	bip44_compat_purpose => 49,
	bip44_segwit_purpose => 84,
};

# These constants are environment-specific and internal only
use constant {
	ivsize => $Config{ivsize},
	is_32bit => $Config{ivsize} == 4,
	is_64bit => $Config{ivsize} >= 8,
};

1;

