package Bitcoin::Crypto::Bech32;

use Modern::Perl "2010";
use Exporter qw(import);
use Math::BigInt 1.999816 try => 'GMP';
use Digest::SHA qw(sha256);

use Bitcoin::Crypto::Helpers qw(pad_hex);

our @EXPORT_OK = qw(
    encode_bech32
    decode_bech32
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

my $CHECKSUM_SIZE = 6;

my @alphabet = qw(
    q p z r y 9 x 8
    g f 2 t v d w 0
    s 3 j n 5 4 k h
    c e 6 m u a 7 l
);

my %alphabet_mapped = map { $alphabet[$_] => $_ } 0 .. $#alphabet;


sub encode_bech32
{
    my ($bytes) = @_;
    my $number = Math::BigInt->from_bytes($bytes);
    my $result = "";
    my $size = scalar @alphabet;
    while ($number->is_pos()) {
        my $copy = $number->copy();
        $result = $alphabet[$copy->bmod($size)] . $result;
        $number->bdiv($size);
    }
    return $result;
}

sub decode_bech32
{
    my ($bech32encoded) = @_;
    my $result = Math::BigInt->new(0);
    my @arr = split "", $bech32encoded;
    while (@arr > 0) {
        my $current = $alphabet_mapped{shift @arr};
        return undef unless defined $current;
        my $step = Math::BigInt->new(scalar @alphabet)->bpow(scalar @arr)->bmul($current);
        $result->badd($step);
    }
    return $result->as_bytes();
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Bech32 - Bitcoin's Bech32 implementation in Perl

=head1 SYNOPSIS

  use Bitcoin::Crypto::Base58 qw(:all);

  my $b58str = encode_base58check(pack "A*", "hello");
  my $bytestr = decode_base58check($b58str);

=head1 DESCRIPTION

Implementation of Base58 and Base58Check algorithm with Math::BigInt (GMP).

=head1 FUNCTIONS

=head2 encode_base58

=head2 decode_base58

Basic base58 encoding / decoding.
Encoding takes one argument which is byte string.
Decoding takes base58-encoded string

=head2 encode_base58_preserve

=head2 decode_base58_preserve

Base58 with leading zero preservation.

=head2 encode_base58check

=head2 decode_base58check

Base58 with leading zero preservation and checksum validation.

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::PrivateKey>

=item L<Bitcoin::Crypto::PublicKey>

=back

=cut
