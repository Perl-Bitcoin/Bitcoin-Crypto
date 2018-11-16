package Bitcoin::Crypto::Base58;

use Modern::Perl "2010";
use Exporter qw(import);
use Math::BigInt;
use Digest::SHA qw(sha256);

use constant CHECKSUM_SIZE => 4;

our @EXPORT_OK = qw(
    encode_base58
    encode_base58_perserve
    encode_base58check
    decode_base58
    decode_base58check
    decode_base58_perserve
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

my @alphabet = qw(
    1 2 3 4 5 6 7 8 9
    A B C D E F G H J K L M N P Q R S T U V W X Y Z
    a b c d e f g h i j k m n o p q r s t u v w x y z
);

my %alphabet_mapped = map { $alphabet[$_] => $_ } keys @alphabet;

sub encode_base58
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

sub encode_base58_perserve
{
    my ($bytes) = @_;
    my $perserve = 0;
    ++$perserve while vec($bytes, $perserve, 8) == 0x00;
    return ($alphabet[0] x $perserve) . encode_base58($bytes);
}

sub encode_base58check
{
    my ($bytes) = @_;
    my $checksum = pack("a" . CHECKSUM_SIZE, sha256(sha256($bytes)));
    return encode_base58_perserve($bytes . $checksum);
}

sub decode_base58
{
    my ($base58encoded) = @_;
    my $result = Math::BigInt->new(0);
    my @arr = split "", $base58encoded;
    while (@arr > 0) {
        my $current = $alphabet_mapped{shift @arr};
        return undef unless defined $current;
        my $step = Math::BigInt->new(58)->bpow(scalar @arr)->bmul($current);
        $result->badd($step);
    }
    return $result->as_bytes();
}

sub decode_base58_perserve
{
    my ($base58encoded) = @_;
    my $perserve = 0;
    ++$perserve while substr($base58encoded, $perserve, 1) eq $alphabet[0];
    my $decoded = decode_base58($base58encoded);
    return undef unless defined $decoded;
    return pack("x$perserve") . $decoded;
}

sub decode_base58check
{
    my ($base58encoded) = @_;
    my $decoded = decode_base58_perserve($base58encoded);
    return undef unless defined $decoded;
    my $encoded_val = substr $decoded, 0, -CHECKSUM_SIZE;
    my $checksum = substr $decoded, -CHECKSUM_SIZE;
    if (unpack("a" . CHECKSUM_SIZE, sha256(sha256($encoded_val))) eq $checksum) {
        return $encoded_val;
    }
    return 0;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Base58 - Bitcoin's Base58 implementation in Perl

=head1 SYNOPSIS

  use Bitcoin::Crypto::Base58Check qw(:all);

  encode_base58check(pack "A*", "hello");

=head1 DESCRIPTION

Implementation of Base58Check algorithm with Math::BigInt.

It seems all the existing implementations of the Base58 either:

=over 2

=item * have external dependencies

=item * have alphabets incompatible with Bitcoin

=item * don't do leading zeros perservation

=back

=head1 FUNCTIONS

=head2 encode_base58($bytestr) / decode_base58($str)

Basic base58 encoding / decoding.
Encoding takes one argument which is byte string.
Decoding takes string

=head2 encode_base58_perserve($bytestr) / decode_base58_perserve($str)

Base58 with leading zero perservation.

=head2 encode_base58check($bytestr) / decode_base58check($str)

Base58 with leading zero perservation and checksum validation.

=head1 SEE ALSO

=over 2

=item Bitcoin::Crypto::PrivateKey

=item Bitcoin::Crypto::PublicKey

=back

=cut
