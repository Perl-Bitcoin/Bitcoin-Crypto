package Bitcoin::Crypto::Helpers;

use Modern::Perl "2010";
use Exporter qw(import);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);

use Bitcoin::Crypto::Exception;

our @EXPORT_OK = qw(
	pad_hex
	ensure_length
	hash160
	hash256
);

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
		"packed string exceeds maximum number of bytes available ($bytelen)"
	) if $missing < 0;

	return pack("x$missing") . $packed;
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
