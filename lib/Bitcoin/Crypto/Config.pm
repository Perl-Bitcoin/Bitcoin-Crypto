package Bitcoin::Crypto::Config;

our $VERSION = "0.997";

use v5.10;
use warnings;

use constant {
	curve_name => "secp256k1",
	max_child_keys => (2 << 30),
	key_max_length => 32,
	wif_compressed_byte => "\x01",
	compress_public_point => 1,
	witness_version => 0,
	max_witness_version => 16,
};

1;
