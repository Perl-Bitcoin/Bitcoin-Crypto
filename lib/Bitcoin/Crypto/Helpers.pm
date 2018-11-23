package Bitcoin::Crypto::Helpers;

use Modern::Perl "2010";
use Exporter qw(import);

our @EXPORT_OK = qw(
    pad_hex
);

sub pad_hex
{
    my ($hex) = @_;
    $hex =~ s/^0x//;
    return "0" x (length($hex) % 2) . $hex;
}

1;
