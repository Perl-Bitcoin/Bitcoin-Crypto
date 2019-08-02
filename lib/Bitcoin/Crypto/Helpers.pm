package Bitcoin::Crypto::Helpers;

use Modern::Perl "2010";
use Exporter qw(import);
use Carp qw(croak);

our @EXPORT_OK = qw(
	pad_hex
	ensure_length
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
	croak "Packed string exceeds maximum number of bytes available ($bytelen)"
		if $missing < 0;
	return pack("x$missing") . $packed;
}

1;