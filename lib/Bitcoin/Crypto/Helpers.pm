package Bitcoin::Crypto::Helpers;

use v5.10; use warnings;
use Exporter qw(import);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Math::BigInt 1.999818 try => 'GMP';

use Bitcoin::Crypto::Exception;

our @EXPORT_OK = qw(
	new_bigint
	pad_hex
	ensure_length
	verify_bytestring
	hash160
	hash256
);

sub new_bigint
{
	my ($bytes) = @_;
	return Math::BigInt->from_hex(unpack "H*", $bytes);

	# return Math::BigInt->from_bytes($bytes);
}

sub pad_hex
{
	my ($hex) = @_;
	$hex =~ s/^0x//;
	return "0" x (length($hex) % 2) . $hex;
}

sub ensure_length
{
	my ($packed, $bytelen) = @_;
	my $missing = $bytelen - length $packed;

	Bitcoin::Crypto::Exception->raise(
		"packed string exceeds maximum number of bytes allowed ($bytelen)"
	) if $missing < 0;

	return pack("x$missing") . $packed;
}

sub verify_bytestring
{
	my ($string) = @_;

	my @characters = split //, $string;

	Bitcoin::Crypto::Exception->raise(
		"string contains characters with numeric values over 255 and cannot be used as a byte string"
	) if (grep { ord($_) > 255 } @characters) > 0;
}

sub hash160
{
	my ($data) = @_;

	return ripemd160(sha256($data));
}

sub hash256
{
	my ($data) = @_;

	return sha256(sha256($data));
}

1;
