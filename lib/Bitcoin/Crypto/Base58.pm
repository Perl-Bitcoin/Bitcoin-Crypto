package Bitcoin::Crypto::Base58;

use Modern::Perl "2010";
use Exporter qw(import);
use Math::BigInt 1.999816 try => 'GMP';

use Bitcoin::Crypto::Helpers qw(hash256);
use Bitcoin::Crypto::Exception;

our @EXPORT_OK = qw(
	encode_base58
	encode_base58_preserve
	encode_base58check
	decode_base58
	decode_base58check
	decode_base58_preserve
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

my $CHECKSUM_SIZE = 4;

my @alphabet = qw(
	1 2 3 4 5 6 7 8 9
	A B C D E F G H J K L M N P Q R S T U V W X Y Z
	a b c d e f g h i j k m n o p q r s t u v w x y z
);

my %alphabet_mapped = map { $alphabet[$_] => $_ } 0 .. $#alphabet;

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

sub encode_base58_preserve
{
	my ($bytes) = @_;
	my $preserve = 0;
	++$preserve while substr($bytes, $preserve, 1) eq "\x00";
	return ($alphabet[0] x $preserve) . encode_base58($bytes);
}

sub encode_base58check
{
	my ($bytes) = @_;
	my $checksum = pack("a" . $CHECKSUM_SIZE, hash256($bytes));
	return encode_base58_preserve($bytes . $checksum);
}

sub decode_base58
{
	my ($base58encoded) = @_;
	my $result = Math::BigInt->new(0);
	my @arr = split "", $base58encoded;
	while (@arr > 0) {
		my $current = $alphabet_mapped{shift @arr};
		Bitcoin::Crypto::Exception::Base58InputFormat->raise(
			"illegal characters in base58 string"
		) unless defined $current;
		my $step = Math::BigInt->new(scalar @alphabet)->bpow(scalar @arr)->bmul($current);
		$result->badd($step);
	}
	return $result->as_bytes();
}

sub decode_base58_preserve
{
	my ($base58encoded) = @_;
	my $preserve = 0;
	++$preserve while substr($base58encoded, $preserve, 1) eq $alphabet[0];
	my $decoded = decode_base58($base58encoded);
	return pack("x$preserve") . $decoded;
}

sub verify_checksum
{
	my ($decoded) = @_;
	my $encoded_val = substr $decoded, 0, -$CHECKSUM_SIZE;
	my $checksum = substr $decoded, -$CHECKSUM_SIZE;
	return unpack("a" . $CHECKSUM_SIZE, hash256($encoded_val)) eq $checksum;
}

sub decode_base58check
{
	my ($base58encoded) = @_;
	my $decoded = decode_base58_preserve($base58encoded);
	Bitcoin::Crypto::Exception::Base58InputChecksum->raise(
		"incorrect base58check checksum"
	) unless verify_checksum($decoded);
	return substr $decoded, 0, -$CHECKSUM_SIZE;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Base58 - Bitcoin's Base58 implementation in Perl

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
Additional errors (other than illegal characters) are thrown.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item Base58InputFormat - input was not suitable for base58 operations due to invalid format

=item Base58InputChecksum - checksum validation has failed

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Key::Public>

=back

=cut
