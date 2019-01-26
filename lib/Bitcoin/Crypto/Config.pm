package Bitcoin::Crypto::Config;


use Modern::Perl "2010";
use Exporter qw(import);

our @EXPORT = qw(
    %config
);

# DO NOT change these values unless you want to experiment with algorithms
our %config = (
    curve_name => "secp256k1",
    key_min_length => 16,
    key_length_step => 4,
    key_max_length => 32,
    wif_compressed_byte => 0x01,
    compress_public_point => 1
);

1;
