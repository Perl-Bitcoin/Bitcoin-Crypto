package Bitcoin::Crypto::Util;

use v5.14;
use warnings;
use Exporter qw(import);
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Helpers qw(parse_formatdesc ecc);
use Bitcoin::Crypto::Constants qw(:key :witness);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

use Bitcoin::Crypto::Util::Internal qw(
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
	merkle_root
	tagged_hash
	lift_x
	has_even_y
	get_taproot_ext
);

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
	merkle_root
	tagged_hash
	lift_x
	has_even_y
	get_taproot_ext
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

signature_for validate_wif => (
	positional => [Str],
);

signature_for validate_segwit => (
	positional => [ByteStr],
);

signature_for get_address_type => (
	positional => [Str, Maybe [Str], {default => undef}],
);

signature_for get_key_type => (
	positional => [ByteStr],
);

signature_for get_public_key_compressed => (
	positional => [ByteStr],
);

signature_for mnemonic_to_seed => (
	positional => [Str, Maybe [Str], {default => undef}],
);

signature_for generate_mnemonic => (
	positional => [PositiveInt, {default => 128}, Str, {default => 'en'}],
);

signature_for mnemonic_from_entropy => (
	positional => [ByteStr, Str, {default => 'en'}],
);

signature_for get_path_info => (
	positional => [Defined],
);

signature_for pack_compactsize => (
	positional => [PositiveOrZeroInt],
);

signature_for unpack_compactsize => (
	positional => [ByteStr, Maybe [ScalarRef [PositiveOrZeroInt]], {default => undef}],
);

signature_for hash160 => (
	positional => [ByteStr],
);

signature_for hash256 => (
	positional => [ByteStr],
);

signature_for merkle_root => (
	positional => [ArrayRef [ByteStr]],
);

signature_for tagged_hash => (
	positional => [Str, ByteStr],
);

signature_for lift_x => (
	positional => [ByteStr],
);

signature_for has_even_y => (
	positional => [ByteStr | InstanceOf ['Bitcoin::Crypto::Key::Public']],
);

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
		merkle_root
		tagged_hash
		lift_x
		has_even_y
		get_taproot_ext
	);

=head1 DESCRIPTION

These are basic utilities for working with Bitcoin. They do not fit well as a
part of other, more specialized packages.

=head1 FUNCTIONS

=head2 validate_wif

	$is_wif = validate_wif($str)

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

	$seed = mnemonic_to_seed($mnemonic, $password = undef);

Transforms the given BIP39 C<$mnemonic> and an optional C<$password> into a
valid BIP32 C<$seed>, which can be fed into
L<Bitcoin::Crypto::Key::ExtPrivate/from_seed>.

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

	$decoded = from_format [$format => $string]

Reverse of L</to_format> - decodes C<$string> into bytestring, treating it as
C<$format>.

I<Note: this is not usually needed to be called explicitly, as every bytestring
parameter of the module will do this conversion implicitly.>

=head2 pack_compactsize

	$bytestr = pack_compactsize($integer)

Serializes C<$integer> as Bitcoin's CompactSize format and returns it as a byte string.

=head2 unpack_compactsize

	$integer = unpack_compactsize($bytestr, $pos = undef)

Deserializes CompactSize from C<$bytestr>, returning an integer.

If C<$pos> is passed, it must be a reference to a scalar containing the
position at which to start the decoding. It will be modified to contain the
next position after the CompactSize. If not, decoding will start at 0 and will raise
an exception if C<$bytestr> contains anything other than CompactSize.

=head2 hash160

	$hash = hash160($data)

This is hash160 used by Bitcoin (C<RIPEMD160> of C<SHA256>)

=head2 hash256

	$hash = hash256($data)

This is hash256 used by Bitcoin (C<SHA256> of C<SHA256>)

=head2 merkle_root

	$hash = merkle_root([$leaf1, $leaf2, ...])

Calculates a merkle root of input array reference. Leaves will be run through a
double SHA256 before calculating the root.

=head2 tagged_hash

	$hash = tagged_hash($tag, $message)

Calculates a tagged hash of C<$message> using C<$tag> as a tag. These hashes
are described in BIP340.

B<Important note about unicode:> this function only accepts UTF8-decoded
strings for C<$tag>, but can't detect whether it got it or not. This will only
become a problem if you use non-ascii tag. If there's a possibility of
non-ascii, always use utf8 and set binmodes to get decoded (wide) characters.

=head2 lift_x

	$public_key = lift_x($xonly_public_key)

This implements C<lift_x> function defined in BIP340. Returns a compressed ECC
public key with even Y coordinate as a bytestring for a given 32-byte bytestring
C<$xonly_public_key>. Throws an exception if the result is not a valid public
key.

=head2 has_even_y

	$even_y = has_even_y($public_key)

This implements C<has_even_y> function defined in BIP340. Returns a boolean for
a given serialized C<$public_key> - a bytestring. Throws an exception if the
argument is not a valid public key.

=head2 get_taproot_ext

	$bytestring = get_taproot_ext($ext_flag, %args)

This function generates a binary ext for C<$ext_flag> used by taproot
transactions. C<%args> and result depend on the value of C<$ext_flag>:

=over

=item * C<$ext_flag = 0>

C<%args> are empty, an empty string is generated.

=item * C<$ext_flag = 1>

C<script_tree> - instance of L<Bitcoin::Crypto::Script::Tree> (required)

C<leaf_id> - integer, identifier of C<script_tree> leaf for current context (required)

C<codesep_pos> - position of last executed codeseparator, or undef if there was none (optional)

Returns ext according to BIP342.

=back

Raises an exception for unknown C<$ext_flag>.

=head1 SEE ALSO

L<https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>

L<https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>

