package Bitcoin::Crypto::Constants;

use v5.10;
use strict;
use warnings;

use Config;

# These constants generally safe to use outside Bitcoin::Crypto code if you
# need them
use constant {
	curve_name => 'secp256k1',
	max_child_keys => (2 << 30),
	key_max_length => 32,
	wif_compressed_byte => "\x01",
	segwit_witness_version => 0,
	taproot_witness_version => 1,
	max_witness_version => 16,

	bip44_purpose => 44,
	bip44_compat_purpose => 49,
	bip44_segwit_purpose => 84,

	units_per_coin => 100_000_000,

	locktime_height_threshold => 500_000_000,
	max_sequence_no => 0xffffffff,

	sighash_all => 0x01,
	sighash_none => 0x02,
	sighash_single => 0x03,
	sighash_anyonecanpay => 0x80,

	p2sh_timestamp_threshold => 1333238400,
	rbf_sequence_no_threshold => 0xffffffff - 2,

	psbt_magic => "\x70\x73\x62\x74\xff",
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

