package Bitcoin::Crypto::Util;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Unicode::Normalize;
use Crypt::KeyDerivation qw(pbkdf2);
use Encode qw(encode);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::BIP39 qw(gen_bip39_mnemonic entropy_to_bip39_mnemonic);
use Try::Tiny;
use Scalar::Util qw(blessed);
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Helpers qw(parse_formatdesc);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

our @EXPORT_OK = qw(
	validate_wif
	validate_segwit
	get_address_type
	get_key_type
	get_public_key_compressed
	generate_mnemonic
	mnemonic_from_entropy
	mnemonic_to_seed
	get_path_info
	from_format
	to_format
	pack_compactsize
	unpack_compactsize
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

signature_for get_address_type => (
	positional => [Str, Maybe [Str], {default => undef}],
);

sub get_address_type
{
	my ($address, $network_id) = @_;

	require Bitcoin::Crypto::Base58;
	require Bitcoin::Crypto::Bech32;
	require Bitcoin::Crypto::Network;

	my $network = Bitcoin::Crypto::Network->get($network_id // ());
	my $type;

	# first, try segwit
	if ($network->supports_segwit) {
		try {
			Bitcoin::Crypto::Exception::SegwitProgram->raise(
				'invalid human readable part in address'
			) unless Bitcoin::Crypto::Bech32::get_hrp($address) eq $network->segwit_hrp;

			my $data = Bitcoin::Crypto::Bech32::decode_segwit($address);
			my $version = ord substr $data, 0, 1, '';

			$type = 'P2TR'
				if $version == Bitcoin::Crypto::Constants::taproot_witness_version
				&& length $data == 32;

			return if $type;

			Bitcoin::Crypto::Exception::SegwitProgram->raise(
				"invalid segwit address of version $version"
			) unless $version == Bitcoin::Crypto::Constants::segwit_witness_version;

			$type = 'P2WPKH' if length $data == 20;
			$type = 'P2WSH' if length $data == 32;

			return if $type;

			Bitcoin::Crypto::Exception::Address->raise(
				'invalid segwit address'
			);
		}
		catch {
			die $_ unless blessed $_ && $_->isa('Bitcoin::Crypto::Exception::Bech32InputFormat');
		};

		return $type if $type;
	}

	# then, try legacy
	try {
		my $data = Bitcoin::Crypto::Base58::decode_base58check($address);
		my $byte = substr $data, 0, 1, '';

		$type = 'P2PKH' if $byte eq $network->p2pkh_byte;
		$type = 'P2SH' if $byte eq $network->p2sh_byte;

		Bitcoin::Crypto::Exception::Address->raise(
			'invalid legacy address'
		) unless length $data == 20;

		return if $type;

		Bitcoin::Crypto::Exception::Address->raise(
			'invalid first byte in address'
		);
	}
	catch {
		die $_ unless blessed $_ && $_->isa('Bitcoin::Crypto::Exception::Base58InputFormat');
	};

	return $type if $type;
	Bitcoin::Crypto::Exception::Address->raise(
		"not an address: $address"
	);
}

signature_for get_key_type => (
	positional => [ByteStr],
);

sub get_key_type
{
	my ($entropy) = @_;

	return 0 if defined get_public_key_compressed($entropy);
	return 1
		if length $entropy <= Bitcoin::Crypto::Constants::key_max_length;
	return undef;
}

signature_for get_public_key_compressed => (
	positional => [ByteStr],
);

sub get_public_key_compressed
{
	my ($entropy) = @_;

	my $curve_size = Bitcoin::Crypto::Constants::key_max_length;
	my $octet = substr $entropy, 0, 1;

	my $has_unc_oc = $octet eq "\x04" || $octet eq "\x06" || $octet eq "\x07";
	my $is_unc = $has_unc_oc && length $entropy == 2 * $curve_size + 1;

	my $has_com_oc = $octet eq "\x02" || $octet eq "\x03";
	my $is_com = $has_com_oc && length $entropy == $curve_size + 1;

	return 1 if $is_com;
	return 0 if $is_unc;
	return undef;
}

signature_for mnemonic_to_seed => (
	positional => [Str, Maybe [Str], {default => undef}],
);

sub mnemonic_to_seed
{
	my ($mnemonic, $password) = @_;

	$mnemonic = encode('UTF-8', NFKD($mnemonic));
	$password = encode('UTF-8', NFKD('mnemonic' . ($password // '')));

	return pbkdf2($mnemonic, $password, 2048, 'SHA512', 64);
}

signature_for generate_mnemonic => (
	positional => [PositiveInt, {default => 128}, Str, {default => 'en'}],
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
	positional => [ByteStr, Str, {default => 'en'}],
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
	positional => [Defined],
);

sub get_path_info
{
	my ($path) = @_;

	# NOTE: ->coerce may still throw because of exceptions in from_string of DerivationPath
	return scalar try {
		DerivationPath->assert_coerce($path);
	};
}

# use signature, not signature_for, because of the prototype
sub from_format ($)
{
	state $sig = signature(positional => [Tuple [FormatStr, Str]]);
	my ($format, $data) = @{($sig->(@_))[0]};

	return parse_formatdesc($format, $data);
}

# use signature, not signature_for, because of the prototype
sub to_format ($)
{
	state $sig = signature(positional => [Tuple [FormatStr, ByteStr]]);
	my ($format, $data) = @{($sig->(@_))[0]};

	return parse_formatdesc($format, $data, 1);
}

signature_for pack_compactsize => (
	positional => [PositiveOrZeroInt],
);

sub pack_compactsize
{
	my ($value) = @_;

	if ($value <= 0xfc) {
		return pack 'C', $value;
	}
	elsif ($value <= 0xffff) {
		return "\xfd" . pack 'v', $value;
	}
	elsif ($value <= 0xffffffff) {
		return "\xfe" . pack 'V', $value;
	}
	else {
		# 32 bit archs should not reach this
		return "\xff" . (pack 'V', $value & 0xffffffff) . (pack 'V', $value >> 32);
	}
}

signature_for unpack_compactsize => (
	positional => [ByteStr, Maybe [ScalarRef [PositiveOrZeroInt]], {default => undef}],
);

sub unpack_compactsize
{
	my ($stream, $pos_ref) = @_;
	my $partial = !!$pos_ref;
	my $pos = $partial ? $$pos_ref : 0;

	# if the first byte is 0xfd, 0xfe or 0xff, then CompactSize contains 2, 4 or 8
	# bytes respectively
	my $value = ord substr $stream, $pos++, 1;
	my $length = 2**($value - 0xfd + 1);

	if ($length > 1) {
		Bitcoin::Crypto::Exception->raise(
			"cannot unpack CompactSize: not enough data in stream"
		) if length $stream < $length;

		if ($length == 2) {
			$value = unpack 'v', substr $stream, $pos, 2;
		}
		elsif ($length == 4) {
			$value = unpack 'V', substr $stream, $pos, 4;
		}
		else {
			Bitcoin::Crypto::Exception->raise(
				"cannot unpack CompactSize: no 64 bit support"
			) if !Bitcoin::Crypto::Constants::is_64bit;

			my $lower = unpack 'V', substr $stream, $pos, 4;
			my $higher = unpack 'V', substr $stream, $pos + 4, 4;
			$value = ($higher << 32) + $lower;
		}

		$pos += $length;
	}

	if ($partial) {
		$$pos_ref = $pos;
	}
	else {
		Bitcoin::Crypto::Exception->raise(
			"cannot unpack CompactSize: leftover data in stream"
		) unless $pos == length $stream;
	}

	return $value;
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

Bitcoin::Crypto::Util - General Bitcoin utilities

=head1 SYNOPSIS

	use Bitcoin::Crypto::Util qw(
		validate_wif
		validate_segwit
		get_address_type
		get_key_type
		get_public_key_compressed
		generate_mnemonic
		mnemonic_from_entropy
		mnemonic_to_seed
		get_path_info
		from_format
		to_format
		pack_compactsize
		unpack_compactsize
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

=head2 get_address_type

	$type = get_address_type($address, $network = Bitcoin::Crypto::Network->get)

Tries to guess the type of C<$address>. Returns C<P2PKH>, C<P2SH>, C<P2WPKH>,
C<P2WSH> or C<P2TR>. May throw Base58, Bech32, SegwitProgram, Address or other
exceptions if the string is not a valid address.

=head2 get_key_type

	$is_private = get_key_type($bytestr);

Checks if the C<$bytestr> looks like a valid ASN X9.62 format (compressed /
uncompressed / hybrid public key or private key entropy up to curve size bits).

Returns boolean which states whether the key is private. Returns
undef if C<$bytestr> does not look like a valid key entropy.

=head2 get_public_key_compressed

	$is_compressed = get_public_key_compressed($bytestr);

Checks if the C<$bytestr> looks like a valid ASN X9.62 format (compressed /
uncompressed / hybrid public key).

Returns boolean which states whether the key is compressed. Returns
undef if C<$bytestr> does not look like a valid public key.

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

Tries to get derivation path data from C<$path>, which can be a string like
C<"m/1/3'"> or an object which implements C<get_derivation_path> method (and
does C<Bitcoin::Crypto::Role::WithDerivationPath>). Returns undef if C<$path>
is not a valid path, otherwise returns the structure as an instance of
L<Bitcoin::Crypto::DerivationPath>:

	{
		private => bool, # is path derivation private (lowercase m)
		path => [
			# derivation path with 2^31 added to every hardened child number
			int, int, ..
		],
	}

You may also use L<Bitcoin::Crypto::Types/DerivationPath> type and its
coercions to achieve the same effect (but with an exception instead of undef on
failure).

=head2 to_format

	$encoded = to_format [$format => $bytes];

Unpacks bytestring C<$bytes> into the given C<$format>. Use this to avoid
manual unpacking.

Supported C<$format> values are:

=over

=item * C<bytes>, does nothing

=item * C<hex>, encodes as a hexadecimal string (no C<0x> prefix)

=item * C<base58>, uses base58 and includes the checksum (base58check)

=item * C<base64>, uses base64

=back

=head2 from_format

	$decoded = from_format [$format => $string];

Reverse of L</to_format> - decodes C<$string> into bytestring, treating it as
C<$format>.

I<Note: this is not usually needed to be called explicitly, as every bytestring
parameter of the module will do this conversion implicitly.>

=head2 pack_compactsize

	$bytestr = pack_compactsize($integer);

Serializes C<$integer> as Bitcoin's CompactSize format and returns it as a byte string.

=head2 unpack_compactsize

	$integer = unpack_compactsize($bytestr, $pos = undef);

Deserializes CompactSize from C<$bytestr>, returning an integer.

If C<$pos> is passed, it must be a reference to a scalar containing the
position at which to start the decoding. It will be modified to contain the
next position after the CompactSize. If not, decoding will start at 0 and will raise
an exception if C<$bytestr> contains anything other than CompactSize.

=head2 hash160

	$hash = hash160($data);

This is hash160 used by Bitcoin (C<RIPEMD160> of C<SHA256>)

=head2 hash256

	$hash = hash256($data);

This is hash256 used by Bitcoin (C<SHA256> of C<SHA256>)

=head1 SEE ALSO

L<https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>

L<https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>

