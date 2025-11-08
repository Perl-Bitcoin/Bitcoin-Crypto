package Bitcoin::Crypto::Constants;

use v5.10;
use strict;
use warnings;

use Config;

# These constants generally safe to use outside Bitcoin::Crypto code if you
# need them
use constant {
	curve_name => 'secp256k1',
	curve_order => pack('H*', 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
	curve_generator => pack(
		'H*',
		'0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
	),

	max_child_keys => (2 << 30),
	key_max_length => 32,
	wif_compressed_byte => "\x01",
	segwit_witness_version => 0,
	taproot_witness_version => 1,
	max_witness_version => 16,

	bip44_purpose => 44,
	bip44_compat_purpose => 49,
	bip44_segwit_purpose => 84,
	bip44_taproot_purpose => 86,

	units_per_coin => 100_000_000,

	locktime_height_threshold => 500_000_000,
	max_sequence_no => 0xffffffff,

	sighash_default => 0x00,
	sighash_all => 0x01,
	sighash_none => 0x02,
	sighash_single => 0x03,
	sighash_anyonecanpay => 0x80,

	script_max_stack_elements => 1000,
	script_max_element_size => 520,
	tapscript_leaf_version => 0xc0,

	p2sh_timestamp_threshold => 1333238400,
	rbf_sequence_no_threshold => 0xffffffff - 2,

	psbt_magic => pack('H*', '70736274ff'),
	psbt_separator => "\x00",
	psbt_global_map => 'global',
	psbt_input_map => 'in',
	psbt_output_map => 'out',
};

# These constants are environment-specific and internal only
use constant {
	ivsize => $Config{ivsize},
	is_32bit => $Config{ivsize} == 4,
	is_64bit => $Config{ivsize} >= 8,
};

1;

