package Bitcoin::Crypto::Key::ExtPrivate;

our $VERSION = "0.996";

use v5.10;
use warnings;
use Moo;
use Crypt::Mac::HMAC qw(hmac);
use Encode qw(encode decode);
use Unicode::Normalize;
use Bitcoin::BIP39 qw(gen_bip39_mnemonic bip39_mnemonic_to_entropy entropy_to_bip39_mnemonic);
use Crypt::KeyDerivation qw(pbkdf2);
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Key::ExtPublic;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(new_bigint pad_hex ensure_length verify_bytestring);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto;

use namespace::clean;
our $VERSION = Bitcoin::Crypto->VERSION;

with "Bitcoin::Crypto::Role::ExtendedKey";

sub _is_private { 1 }

sub generate_mnemonic
{
	my ($class, $len, $lang) = @_;
	my ($min_len, $len_div, $max_len) = (128, 32, 256);
	$len //= $min_len;
	$lang //= "en";

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

sub mnemonic_from_entropy
{
	my ($class, $entropy, $lang) = @_;
	$lang //= "en";

	return Bitcoin::Crypto::Exception::MnemonicGenerate->trap_into(
		sub {
			entropy_to_bip39_mnemonic(
				entropy => $entropy,
				language => $lang
			);
		}
	);
}

sub from_mnemonic
{
	my ($class, $mnemonic, $password, $lang) = @_;
	$mnemonic = encode("UTF-8", NFKD(decode("UTF-8", $mnemonic)));
	$password = encode("UTF-8", NFKD(decode("UTF-8", "mnemonic" . ($password // ""))));

	if (defined $lang) {

		# checks validity of seed in given language
		# requires Wordlist::LANG::BIP39 module for given LANG
		Bitcoin::Crypto::Exception::MnemonicCheck->trap_into(
			sub {
				bip39_mnemonic_to_entropy(
					mnemonic => $mnemonic,
					language => $lang
				);
			}
		);
	}
	my $bytes = pbkdf2($mnemonic, $password, 2048, "SHA512", 64);

	return $class->from_seed($bytes);
}

sub from_seed
{
	my ($class, $seed) = @_;
	verify_bytestring($seed);

	my $bytes = hmac("SHA512", "Bitcoin seed", $seed);
	my $key = substr $bytes, 0, 32;
	my $cc = substr $bytes, 32, 32;

	return $class->new($key, $cc);
}

sub from_hex_seed
{
	my ($class, $seed) = @_;

	return $class->from_seed(pack "H*", pad_hex $seed);
}

sub get_public_key
{
	my ($self) = @_;

	my $public = Bitcoin::Crypto::Key::ExtPublic->new(
		$self->raw_key("public"),
		$self->chain_code,
		$self->child_number,
		$self->parent_fingerprint,
		$self->depth
	);
	$public->set_network($self->network);

	return $public;
}

sub _derive_key_partial
{
	my ($self, $child_num, $hardened) = @_;

	my $hmac_data;
	if ($hardened) {

		# zero byte
		$hmac_data .= "\x00";

		# key data - 32 bytes
		$hmac_data .= ensure_length $self->raw_key, $config{key_max_length};
	}
	else {
		# public key data - SEC compressed form
		$hmac_data .= $self->raw_key("public_compressed");
	}

	# child number - 4 bytes
	$hmac_data .= ensure_length pack("N", $child_num), 4;

	my $data = hmac("SHA512", $self->chain_code, $hmac_data);
	my $chain_code = substr $data, 32, 32;

	my $number = new_bigint(substr $data, 0, 32);
	my $key_num = new_bigint($self->raw_key);
	my $n_order = new_bigint(pack "H*", $self->key_instance->curve2hash->{order});

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"key $child_num in sequence was found invalid"
	) if $number->bge($n_order);

	$number->badd($key_num);
	$number->bmod($n_order);

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"key $child_num in sequence was found invalid"
	) if $number->beq(0);

	return (blessed $self)->new(
		$number->as_bytes,
		$chain_code,
		$child_num,
		$self->get_fingerprint,
		$self->depth + 1
	);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::ExtPrivate - class for Bitcoin extended private keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::ExtPrivate;

	# generate mnemonic words first
	my $mnemonic = Bitcoin::Crypto::Key::ExtPrivate->generate_mnemonic;
	print "Your mnemonic is: $mnemonic";

	# create ExtPrivateKey from mnemonic (without password)
	my $key = Bitcoin::Crypto::Key::ExtPrivate->from_mnemonic($mnemonic);
	my $ser_key = $key->to_serialized_base58;
	print "Your exported master key is: $ser_key";

	# derive child private key
	my $path = "m/0'";
	my $child_key = $key->derive_key($path);
	my $ser_child_key = $child_key->to_serialized_base58;
	print "Your exported $path child key is: $ser_child_key";

	# create basic keypair
	my $basic_private = $child_key->get_basic_key;
	my $basic_public = $child_key->get_public_key->get_basic_key;

=head1 DESCRIPTION

This class allows you to create an extended private key instance.

You can use an extended private key to:

=over 2

=item * generate extended public keys

=item * derive extended keys using a path

=item * restore keys from mnemonic codes, seeds and base58 format

=back

see L<Bitcoin::Crypto::Network> if you want to work with other networks than Bitcoin Mainnet.

=head1 METHODS

=head2 generate_mnemonic

	sig: generate_mnemonic($class, $len = 128, $lang = "en")

Generates a new mnemonic code. Default entropy is 128 bits.
With $len this can be changed to up to 256 bits with 32 bit step.

Other languages than english require additional modules for L<Bitcoin::BIP39>.

Dies when $len is invalid (under 128, above 256 or not divisible by 32).
Returns newly generated BIP39 mnemonic string.

In some environments a problem may be encountered that causes the secure random bytes generator to block the program execution (See L<Bytes::Random::Secure/"BLOCKING ENTROPY SOURCE">). In this case you can use I<mnemonic_from_entropy> and pass in entropy generated by L<Bytes::Random::Secure> in non-blocking mode (via the OO interface).

=head2 mnemonic_from_entropy

	sig: mnemonic_from_entropy($class, $bytes, $lang = "en")

Generates a new mnemonic code from custom entropy given in $bytes (a bytestring). This entropy should be of the same bit size as in L</"generate_mnemonic">. Returns newly generated BIP39 mnemonic string.

This can be useful to avoid relying on the underlying implementation of L<Bitcoin::BIP39>.

Another use would be implementing one's own entropy source that can be truly random, not just cryptographically-secure. A popular example would be capturing user's mouse movements.

Be aware that the method you use to generate a mnemonic will be a very important factor in your key's security. If possible, use real sources of randomness (not pseudo-random) or a cryptographically secure pseduo-random number generator like the one used by L<Bytes::Random::Secure>.

=head2 from_mnemonic

	sig: from_mnemonic($class, $mnemonic, $password = "", $lang = undef)

Creates a new key from given mnemonic and password.

Note that technically any password is correct and there's no way to tell if it was mistaken.

If you need to validate if $mnemonic is a valid mnemonic you should specify $lang, e.g. "en".

If no $lang is given then any string passed as $mnemonic will produce a valid key.

Returns a new instance of this class.

=head2 from_seed

	sig: from_seed($class, $seed)

Creates and returns a new key from seed, which can be any data of any length.  $seed is expected to be a byte string.

=head2 from_hex_seed

	sig: from_hex_seed($class, $seed)

Same as from_seed, but $seed is treated as hex string.

=head2 to_serialized

	sig: to_serialized($self)

Returns the key serialized in format specified in BIP32 as byte string.

=head2 to_serialized_base58

	sig: to_serialized_base58($self)

Behaves the same as to_serialized(), but performs Base58Check encoding on the resulting byte string.

=head2 from_serialized

	sig: from_serialized($class, $serialized, $network = undef)

Tries to unserialize byte string $serialized with format specified in BIP32.

Dies on errors. If multiple networks match serialized data specify $network manually (id of the network) to avoid exception.

=head2 from_serialized_base58

	sig: from_serialized_base58($class, $base58, $network = undef)

Same as from_serialized, but performs Base58Check decoding on $base58 argument.

=head2 set_network

	sig: set_network($self, $val)

Change key's network state to $val. It can be either network name present in Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 get_public_key

	sig: get_public_key($self)

Returns instance of L<Bitcoin::Crypto::Key::ExtPublic> generated from the private key.

=head2 get_basic_key

	sig: get_basic_key($self)

Returns the key in basic format: L<Bitcoin::Crypto::Key::Private>

=head2 derive_key

	sig: derive_key($self, $path)

Performs extended key derivation as specified in BIP32 on the current key with $path. Dies on error.

See BIP32 document for details on derivation paths and methods.

Returns a new extended key instance - result of a derivation.

=head2 get_fingerprint

	sig: get_fingerprint($self, $len = 4)

Returns a fingerprint of the extended key of $len length (byte string)

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * MnemonicGenerate - mnemonic couldn't be generated correctly

=item * MnemonicCheck - mnemonic didn't pass the validity check

=item * KeyDerive - key couldn't be derived correctly

=item * KeyCreate - key couldn't be created correctly

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::ExtPublic>

=item L<Bitcoin::Crypto::Network>

=back

=cut
