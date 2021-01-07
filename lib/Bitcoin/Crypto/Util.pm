package Bitcoin::Crypto::Util;

use v5.10;
use warnings;
use Exporter qw(import);
use List::Util qw(first);
use Crypt::PK::ECC;

use Bitcoin::Crypto;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Base58 qw(decode_base58check);

our $VERSION = Bitcoin::Crypto->VERSION;

our @EXPORT_OK = qw(
	validate_wif
	get_key_type
	get_path_info
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

sub validate_wif
{
	my ($wif) = @_;
	my $byte_wif = decode_base58check($wif);
	my $last_byte = substr $byte_wif, -1;
	if (length $byte_wif == $config{key_max_length} + 2) {
		return $last_byte eq $config{wif_compressed_byte};
	}
	else {
		return length $byte_wif == $config{key_max_length} + 1;
	}
}

sub get_key_type
{
	my ($entropy) = @_;

	my $curve_size = $config{key_max_length};
	my $octet = substr $entropy, 0, 1;

	my $has_unc_oc = $octet eq "\x04" || $octet eq "\x06" || $octet eq "\x07";
	my $is_unc = $has_unc_oc && length $entropy == 2 * $curve_size + 1;

	my $has_com_oc = $octet eq "\x02" || $octet eq "\x03";
	my $is_com = $has_com_oc && length $entropy == $curve_size + 1;

	return 0
		if $is_com || $is_unc;
	return 1
		if length $entropy <= $curve_size;
	return;
}

sub get_path_info
{
	my ($path) = @_;
	if ($path =~ m#^([mM])((?:/\d+'?)*)$#) {
		my %info;
		$info{private} = $1 eq "m";
		if (defined $2 && length $2 > 0) {
			$info{path} =
				[map { s#(\d+)'#$1 + $config{max_child_keys}#e; $_ } split "/", substr $2, 1];
		}
		else {
			$info{path} = [];
		}
		return undef if first { $_ >= $config{max_child_keys} * 2 }
			@{$info{path}};
		return \%info;
	}
	else {
		return undef;
	}
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Util - Basic utilities for working with bitcoin

=head1 SYNOPSIS

	use Bitcoin::Crypto::Util qw(
		validate_wif
		get_key_type
		get_path_info
	);

=head1 DESCRIPTION

These are basic utilities for working with bitcoin, used by other packages.

=head1 FUNCTIONS

=head2 validate_wif

	my $bool = validate_wif($str);

Ensures Base58 encoded string looks like encoded private key in WIF format.
Throws an exception if $str is not valid base58.

=head2 get_key_type

	my $is_private = get_key_type($bytestr);

Checks if the $bytestr looks like a valid ASN X9.62 format (compressed / uncompressed / hybrid public key or private key entropy up to curve size bits).
Returns boolean which can be used to determine if the key is private.
Returns undef if $bytestr does not look like a valid key entropy.

=head2 get_path_info

	my $path = "m/1/3'";
	my $path_data = get_path_info($path);

Tries to get derivation path data from $path.
Returns undef if $path is not a valid path.
Otherwise returns the structure:

	{
		private => bool, # is path derivation private (lowercase m)
		path => [
			# derivation path with 2^31 added to every hardened child number
			int, int, ..
		],
	}

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=back

=cut
