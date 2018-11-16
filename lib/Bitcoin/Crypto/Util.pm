package Bitcoin::Crypto::Util;

use Modern::Perl "2010";
use Exporter qw(import);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Base58 qw(decode_base58check);

our @EXPORT_OK = qw(
    pack_hex
    validate_address
    validate_wif
);

sub pack_hex
{
    my ($hex_based) = @_;
    #complete hex to full bytes with leading zeros
    return pack "H*", "0" x (length($hex_based) % 2) . $hex_based;
}

sub validate_address
{
    my ($address) = @_;
    my $byte_address = decode_base58check($address);
    return $byte_address unless $byte_address;
    # 20 bytes for RIPEMD160, 1 byte for network
    return length $byte_address == 21;
}

sub validate_wif
{
    my ($wif) = @_;
    my $byte_wif = decode_base58check($wif);
    return $byte_wif unless $byte_wif;
    my $last_byte = substr $byte_wif, -1;
    if (length $byte_wif == $config{key_max_length} + 2) {
        return ord($last_byte) == $config{wif_compressed_byte};
    } else {
        return length $byte_wif == $config{key_max_length} + 1;
    }
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Util - Basic utilities for working with bitcoin

=head1 SYNOPSIS

  use Bitcoin::Crypto::Util qw(
      pack_hex
      validate_address
      validate_wif
  );

=head1 DESCRIPTION

These are basic utilities for working with bitcoin, used by other packages.

=head1 FUNCTIONS

=head2 pack_hex($str)

Ensures hex data is packed correctly by adding leading zero to uneven length
hex string.
Returns byte string.

=head2 validate_address($str)

Ensures Base58 encoded string looks like encoded address.

=head2 validate_wif($str)

Ensures Base58 encoded string looks like encoded private key in WIF format.

=head1 SEE ALSO

=over 2

=item Bitcoin::Crypto::PrivateKey

=item Bitcoin::Crypto::PublicKey

=back

=cut
