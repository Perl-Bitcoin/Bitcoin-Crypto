package Bitcoin::Crypto::Base58;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Crypt::Misc qw(encode_b58b decode_b58b);
use Type::Params -sigs;

use Bitcoin::Crypto::Util qw(hash256);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Str ByteStr);

our @EXPORT_OK = qw(
	encode_base58
	encode_base58check
	decode_base58
	decode_base58check
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

my $CHECKSUM_SIZE = 4;

sub verify_checksum
{
	my ($decoded) = @_;
	my $encoded_val = substr $decoded, 0, -$CHECKSUM_SIZE;
	my $checksum = substr $decoded, -$CHECKSUM_SIZE;
	return unpack('a' . $CHECKSUM_SIZE, hash256($encoded_val)) eq $checksum;
}

signature_for encode_base58 => (
	positional => [ByteStr],
);

sub encode_base58
{
	my ($bytes) = @_;

	return encode_b58b($bytes);
}

signature_for encode_base58check => (
	positional => [ByteStr],
);

sub encode_base58check
{
	my ($bytes) = @_;

	my $checksum = pack('a' . $CHECKSUM_SIZE, hash256($bytes));
	return encode_base58($bytes . $checksum);
}

signature_for decode_base58 => (
	positional => [Str],
);

sub decode_base58
{
	my ($base58encoded) = @_;

	my $decoded = decode_b58b($base58encoded);
	Bitcoin::Crypto::Exception::Base58InputFormat->raise(
		'illegal characters in base58 string'
	) unless defined $decoded;

	return $decoded;
}

signature_for decode_base58check => (
	positional => [Str],
);

sub decode_base58check
{
	my ($base58encoded) = @_;

	my $decoded = decode_base58($base58encoded);
	Bitcoin::Crypto::Exception::Base58InputChecksum->raise(
		'incorrect base58check checksum'
	) unless verify_checksum($decoded);

	return substr $decoded, 0, -$CHECKSUM_SIZE;
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Base58 - Bitcoin base58 helpers

=head1 SYNOPSIS

	# none exported by default
	use Bitcoin::Crypto::Base58 qw(
		encode_base58
		decode_base58
		encode_base58check
		decode_base58check
	);

	my $b58str = encode_base58check(pack 'A*', 'hello');
	my $bytestr = decode_base58check($b58str);

=head1 DESCRIPTION

Implementation of Base58Check algorithm and alias to CryptX C<encode_b58b> / C<decode_b58b>

=head1 FUNCTIONS

This module is based on Exporter. None of the functions are exported by default. C<:all> tag exists that exports all the functions at once.

=head2 encode_base58

=head2 decode_base58

Basic base58 encoding / decoding.

Encoding takes one argument which is byte string.

Decoding takes base58-encoded string

These two functions are just aliases to L<Crypt::Misc/encode_b58b> and
L<Crypt::Misc/decode_b58b> with some error checking.

=head2 encode_base58check

=head2 decode_base58check

Base58 with checksum validation. These functions are used with Bitcoin legacy /
compatibility addresses.

Arguments are the same as base functions mentioned above.

Additional errors (other than illegal characters) are thrown.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * Base58InputFormat - input was not suitable for base58 operations due to invalid format

=item * Base58InputChecksum - checksum validation has failed

=back

=head1 SEE ALSO

=over 2

=item L<Crypt::Misc>

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Key::Public>

=back

=cut

