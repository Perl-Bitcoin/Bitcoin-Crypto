package Bitcoin::Crypto::Util;

use Modern::Perl "2010";
use Exporter qw(import);
use List::Util qw(first);
use Try::Tiny;
use Crypt::PK::ECC;

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Base58 qw(decode_base58check);

our @EXPORT_OK = qw(
    validate_address
    validate_wif
    get_key_type
    get_path_info
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

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

sub get_key_type
{
    my ($entropy) = @_;
    my $key = Crypt::PK::ECC->new;
    try {
        $key->import_key_raw($entropy, $config{curve_name});
        return $key->is_private;
    } catch {
        return undef;
    };
}

sub get_path_info
{
    my ($path) = @_;
    if ($path =~ m#^([mM])((?:/\d+'?)*)$#) {
        my %info;
        $info{private} = $1 eq "m";
        if (defined $2 && length $2 > 0) {
            $info{path} = [map { s#(\d+)'#$1 + $config{max_child_keys}#er } split "/", substr $2, 1];
        } else {
            $info{path} = [];
        }
        return undef if first { $_ >= $config{max_child_keys} * 2 } @{$info{path}};
        return \%info;
    } else {
        return undef;
    }
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Util - Basic utilities for working with bitcoin

=head1 SYNOPSIS

  use Bitcoin::Crypto::Util qw(
      validate_address
      validate_wif
  );

=head1 DESCRIPTION

These are basic utilities for working with bitcoin, used by other packages.

=head1 FUNCTIONS

=head2 validate_address($str)

Ensures Base58 encoded string looks like encoded address.

=head2 validate_wif($str)

Ensures Base58 encoded string looks like encoded private key in WIF format.

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::PrivateKey>

=item L<Bitcoin::Crypto::PublicKey>

=back

=cut
