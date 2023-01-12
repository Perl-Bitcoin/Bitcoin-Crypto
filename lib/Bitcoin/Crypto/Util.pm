package Bitcoin::Crypto::Util;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Crypt::PK::ECC;
use Unicode::Normalize;
use Crypt::KeyDerivation qw(pbkdf2);
use Encode qw(encode);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Base58 qw(decode_base58check);

our @EXPORT_OK = qw(
	validate_wif
	get_key_type
	mnemonic_to_seed
	get_path_info
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

sub validate_wif
{
	my ($wif) = @_;
	my $byte_wif = decode_base58check($wif);
	my $last_byte = substr $byte_wif, -1;
	if (length $byte_wif == Bitcoin::Crypto::Config::key_max_length + 2) {
		return $last_byte eq Bitcoin::Crypto::Config::wif_compressed_byte;
	}
	else {
		return length $byte_wif == Bitcoin::Crypto::Config::key_max_length + 1;
	}
}

sub get_key_type
{
	my ($entropy) = @_;

	my $curve_size = Bitcoin::Crypto::Config::key_max_length;
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

sub mnemonic_to_seed
{
	my ($mnemonic, $password) = @_;

	$mnemonic = encode('UTF-8', NFKD($mnemonic));
	$password = encode('UTF-8', NFKD('mnemonic' . ($password // '')));

	return pbkdf2($mnemonic, $password, 2048, 'SHA512', 64);
}

sub get_path_info
{
	my ($path) = @_;
	if ($path =~ m{\A ([mM]) ((?: / \d+ '?)*) \z}x) {
		my ($head, $rest) = ($1, $2);
		my @path;

		if (defined $rest && length $rest > 0) {
			# remove leading slash (after $head)
			substr $rest, 0, 1, '';

			for my $part (split '/', $rest) {
				my $is_hardened = $part =~ tr/'//d;

				return undef if $part >= Bitcoin::Crypto::Config::max_child_keys;

				$part += Bitcoin::Crypto::Config::max_child_keys if $is_hardened;
				push @path, $part;
			}
		}

		return {
			private => $head eq 'm',
			path => \@path,
		};
	}

	return undef;
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

	$bool = validate_wif($str);

Ensures Base58 encoded string looks like encoded private key in WIF format.
Throws an exception if C<$str> is not valid base58.

=head2 get_key_type

	$is_private = get_key_type($bytestr);

Checks if the C<$bytestr> looks like a valid ASN X9.62 format (compressed / uncompressed / hybrid public key or private key entropy up to curve size bits).
Returns boolean which can be used to determine if the key is private.
Returns undef if C<$bytestr> does not look like a valid key entropy.

=head2 mnemonic_to_seed

	$seed = mnemonic_to_seed($mnemonic, $password);

Transforms the given BIP39 C<$mnemonic> and C<$password> into a valid BIP32 C<$seed>, which can be fed into L<Bitcoin::Crypto::Key::ExtPrivate/from_seed>.

C<$seed> is a 512 bit bytestring (64 characters). C<$mnemonic> should be a BIP39 mnemonic, but will not be checked against a dictionary.

This function is only useful if you need a seed instead of mnemonic (for example, you use a wallet implementation which does not implement BIP39). If you only want to create a private key from mnemonic, you should consider using L<Bitcoin::Crypto::Key::ExtPrivate/from_mnemonic> instead.

B<Important note about unicode:> this function only accepts UTF8-decoded strings (both C<$mnemonic> and C<$password>), but can't detect whether it got it or not. This will only become a problem if you use non-ascii mnemonic and/or password. If there's a possibility of non-ascii, always use utf8 and set binmodes to get decoded (wide) characters to avoid problems recovering your wallet.

=head2 get_path_info

	$path_data = get_path_info($path);

Tries to get derivation path data from C<$path>.
Returns undef if C<$path> is not a valid path.
Otherwise returns the structure:

	{
		private => bool, # is path derivation private (lowercase m)
		path => [
			# derivation path with 2^31 added to every hardened child number
			int, int, ..
		],
	}

Example:

	my $path = "m/1/3'";
	my $path_data = get_path_info($path);

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=back

=cut

