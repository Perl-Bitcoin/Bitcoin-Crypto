package Bitcoin::Crypto::Util;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Crypt::PK::ECC;
use Unicode::Normalize;
use Crypt::KeyDerivation qw(pbkdf2);
use Encode qw(encode);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::BIP39 qw(gen_bip39_mnemonic entropy_to_bip39_mnemonic);
use Type::Params -sigs;

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types qw(Str ByteStr FormatStr InstanceOf Maybe PositiveInt Tuple);
use Bitcoin::Crypto::Exception;

our @EXPORT_OK = qw(
	validate_wif
	validate_segwit
	get_key_type
	generate_mnemonic
	mnemonic_from_entropy
	mnemonic_to_seed
	get_path_info
	to_format
	hash160
	hash256
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

signature_for validate_wif => (
	positional => [Str],
);

sub validate_wif
{
	my ($wif) = @_;

	require Bitcoin::Crypto::Base58;
	my $byte_wif = Bitcoin::Crypto::Base58::decode_base58check($wif);

	my $last_byte = substr $byte_wif, -1;
	if (length $byte_wif == Bitcoin::Crypto::Constants::key_max_length + 2) {
		return $last_byte eq Bitcoin::Crypto::Constants::wif_compressed_byte;
	}
	else {
		return length $byte_wif == Bitcoin::Crypto::Constants::key_max_length + 1;
	}
}

signature_for validate_segwit => (
	positional => [ByteStr],
);

sub validate_segwit
{
	my ($program) = @_;

	my $version = unpack 'C', $program;
	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		'incorrect witness program version ' . ($version // '[null]')
	) unless defined $version && $version >= 0 && $version <= Bitcoin::Crypto::Constants::max_witness_version;

	$program = substr $program, 1;

	# common validator
	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		'incorrect witness program length'
	) unless length $program >= 2 && length $program <= 40;

	if ($version == 0) {
		# SegWit validator
		Bitcoin::Crypto::Exception::SegwitProgram->raise(
			'incorrect witness program length (segwit)'
		) unless length $program == 20 || length $program == 32;
	}
	elsif ($version == 1) {
		# Taproot validator

		# taproot outputs are 32 bytes, but other lengths "remain unencumbered"
		# do not throw this exception to make bip350 test suite pass (10-Bech32.t)

		# Bitcoin::Crypto::Exception::SegwitProgram->raise(
		# 	'incorrect witness program length (taproot)'
		# ) unless length $program == 32;
	}

	return $version;
}

signature_for get_key_type => (
	positional => [ByteStr],
);

sub get_key_type
{
	my ($entropy) = @_;

	my $curve_size = Bitcoin::Crypto::Constants::key_max_length;
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

signature_for mnemonic_to_seed => (
	positional => [Str, Maybe[Str], { optional => 1 }],
);

sub mnemonic_to_seed
{
	my ($mnemonic, $password) = @_;

	$mnemonic = encode('UTF-8', NFKD($mnemonic));
	$password = encode('UTF-8', NFKD('mnemonic' . ($password // '')));

	return pbkdf2($mnemonic, $password, 2048, 'SHA512', 64);
}

signature_for generate_mnemonic => (
	positional => [PositiveInt, { default => 128 }, Str, { default => 'en' }],
);

sub generate_mnemonic
{
	my ($len, $lang) = @_;
	my ($min_len, $len_div, $max_len) = (128, 32, 256);

	# bip39 specification values
	Bitcoin::Crypto::Exception::MnemonicGenerate->raise(
		"required entropy of between $min_len and $max_len bits, divisible by $len_div"
	) if $len < $min_len || $len > $max_len || $len % $len_div != 0;

	return Bitcoin::Crypto::Exception::MnemonicGenerate->trap_into(
		sub {
			my $ret = gen_bip39_mnemonic(bits => $len, language => $lang);
			$ret->{mnemonic};
		}
	);
}

signature_for mnemonic_from_entropy => (
	positional => [ByteStr, Str, { default => 'en' }],
);

sub mnemonic_from_entropy
{
	my ($entropy, $lang) = @_;

	return Bitcoin::Crypto::Exception::MnemonicGenerate->trap_into(
		sub {
			entropy_to_bip39_mnemonic(
				entropy => $entropy,
				language => $lang
			);
		}
	);
}

signature_for get_path_info => (
	positional => [Str | InstanceOf['Bitcoin::Crypto::BIP44']],
);

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

				return undef if $part >= Bitcoin::Crypto::Constants::max_child_keys;

				$part += Bitcoin::Crypto::Constants::max_child_keys if $is_hardened;
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

# use signature, not signature_for, because of the prototype
sub to_format ($)
{
	state $sig = signature(positional => [Tuple[FormatStr, ByteStr]]);
	my ($format, $data) = @{($sig->(@_))[0]};

	if ($format eq 'hex') {
		$data = unpack 'H*', $data;
	}
	elsif ($format eq 'base58') {
		require Bitcoin::Crypto::Base58;
		$data = Bitcoin::Crypto::Base58::encode_base58check($data);
	}

	return $data;
}

signature_for hash160 => (
	positional => [ByteStr],
);

sub hash160
{
	my ($data) = @_;

	return ripemd160(sha256($data));
}

signature_for hash256 => (
	positional => [ByteStr],
);

sub hash256
{
	my ($data) = @_;

	return sha256(sha256($data));
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Util - Utilities for working with Bitcoin

=head1 SYNOPSIS

	use Bitcoin::Crypto::Util qw(
		validate_wif
		validate_segwit
		get_key_type
		generate_mnemonic
		mnemonic_from_entropy
		mnemonic_to_seed
		get_path_info
		hash160
		hash256
	);

=head1 DESCRIPTION

These are basic utilities for working with Bitcoin. They do not fit well as a
part of other, more specialized packages.

=head1 FUNCTIONS

=head2 validate_wif

	$bool = validate_wif($str);

Ensures Base58 encoded string looks like encoded private key in WIF format.
Throws an exception if C<$str> is not valid base58.

=head2 validate_segwit

	$segwit_version = validate_segwit($program)

Performs a segwit program validation on C<$program>, which is expected to be a
byte string in which the first byte is a segwit version.

The function returns the detected segwit program version. Note that it does not
perform any more checks than ensuring the byte string is in correct format.

The current implementation is in line with validations for segwit versions C<0>
and C<1>. Future segwit version addresses will work just fine, but no special
validation will be performed until implemented.

Raises an exception (C<Bitcoin::Crypto::Exception::SegwitProgram>) on error.
Returns the detected segwit program version.

=head2 get_key_type

	$is_private = get_key_type($bytestr);

Checks if the C<$bytestr> looks like a valid ASN X9.62 format (compressed /
uncompressed / hybrid public key or private key entropy up to curve size bits).

Returns boolean which states whether the key is private. Returns
undef if C<$bytestr> does not look like a valid key entropy.

=head2 generate_mnemonic

	$mnemonic = generate_mnemonic($len = 128, $lang = 'en')

Generates a new mnemonic code using L<Bytes::Random::Secure>. Default entropy
is C<128> bits. This can be increased up to C<256> bits (increasing by C<32>
bits each step) with C<$len> argument.

Other languages than english require installation of additional modules
language-specific for L<Bitcoin::BIP39>.

Returns newly generated BIP39 mnemonic string. Dies when C<$len> is invalid
(less than C<128>, more than C<256> or not divisible by C<32>).

In some environments a problem may be encountered that causes the secure random
bytes generator to block the program execution (See
L<Bytes::Random::Secure/"BLOCKING ENTROPY SOURCE">). In this case you can use
L</mnemonic_from_entropy> and pass in entropy generated by
L<Bytes::Random::Secure> in non-blocking mode (via the OO interface).

=head2 mnemonic_from_entropy

	$mnemonic = mnemonic_from_entropy($bytes, $lang = 'en')

Generates a new mnemonic code from custom entropy given in C<$bytes> (a
bytestring). This entropy should be of the same bit size as in
L</"generate_mnemonic">. Returns newly generated BIP39 mnemonic string.

This can be useful to avoid relying on the underlying PRNG implementation used
by L<Bitcoin::BIP39>.

Another use would be implementing one's own entropy source that can be truly
random, not just cryptographically-secure. A popular example would be capturing
user's mouse movements.

Be aware that the method you use to generate a mnemonic will be a very
important factor in your key's security. If possible, use real sources of
randomness (not pseudo-random) or a cryptographically secure pseduo-random
number generator like the one used by L<Bytes::Random::Secure>.

=head2 mnemonic_to_seed

	$seed = mnemonic_to_seed($mnemonic, $password);

Transforms the given BIP39 C<$mnemonic> and C<$password> into a valid BIP32
C<$seed>, which can be fed into L<Bitcoin::Crypto::Key::ExtPrivate/from_seed>.

C<$seed> is a C<512> bit bytestring (64 characters). C<$mnemonic> should be a
BIP39 mnemonic, but will not be checked against a dictionary.

This function is only useful if you need a seed instead of mnemonic (for
example, you use a wallet implementation which does not implement BIP39). If
you only want to create a private key from mnemonic, you should consider using
L<Bitcoin::Crypto::Key::ExtPrivate/from_mnemonic> instead.

B<Important note about unicode:> this function only accepts UTF8-decoded
strings (both C<$mnemonic> and C<$password>), but can't detect whether it got
it or not. This will only become a problem if you use non-ascii mnemonic and/or
password. If there's a possibility of non-ascii, always use utf8 and set
binmodes to get decoded (wide) characters to avoid problems recovering your
wallet.

=head2 get_path_info

	$path_data = get_path_info($path);

Tries to get derivation path data from C<$path>  (like C<"m/1/3'">). Returns
undef if C<$path> is not a valid path, otherwise returns the structure:

	{
		private => bool, # is path derivation private (lowercase m)
		path => [
			# derivation path with 2^31 added to every hardened child number
			int, int, ..
		],
	}

=head2 hash160

	my $hash = hash160($data);

This is hash160 used by Bitcoin (C<RIPEMD160> of C<SHA256>)

=head2 hash256

	my $hash = hash256($data);

This is hash256 used by Bitcoin (C<SHA256> of C<SHA256>)

=head1 SEE ALSO

L<https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>

L<https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>

