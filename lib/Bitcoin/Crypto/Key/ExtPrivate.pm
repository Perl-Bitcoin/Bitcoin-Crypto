package Bitcoin::Crypto::Key::ExtPrivate;

our $VERSION = "1.001";

use v5.10;
use strict;
use warnings;
use Moo;
use Crypt::Mac::HMAC qw(hmac);
use Bitcoin::BIP39 qw(gen_bip39_mnemonic bip39_mnemonic_to_entropy entropy_to_bip39_mnemonic);
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::BIP44;
use Bitcoin::Crypto::Key::ExtPublic;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(new_bigint pad_hex ensure_length verify_bytestring);
use Bitcoin::Crypto::Util qw(mnemonic_to_seed);
use Bitcoin::Crypto::Exception;

use namespace::clean;

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

	return $class->from_seed(mnemonic_to_seed($mnemonic, $password));
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

sub derive_key_bip44
{
	my ($self, %data) = @_;
	my $path = Bitcoin::Crypto::BIP44->new(
		%data,
		coin_type => $self,
	);

	return $self->derive_key($path);
}

sub _derive_key_partial
{
	my ($self, $child_num, $hardened) = @_;

	my $hmac_data;
	if ($hardened) {

		# zero byte
		$hmac_data .= "\x00";

		# key data - 32 bytes
		$hmac_data .= ensure_length $self->raw_key, Bitcoin::Crypto::Config::key_max_length;
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

Bitcoin::Crypto::Key::ExtPrivate - Bitcoin extended private keys

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

	$mnemonic = $class->generate_mnemonic($len = 128, $lang = "en")

Generates a new mnemonic code using L<Bytes::Random::Secure>. Default entropy is 128 bits.
With C<$len> this can be changed to up to 256 bits with 32 bit step.

Other languages than english require additional modules for L<Bitcoin::BIP39>.

Returns newly generated BIP39 mnemonic string.
Dies when C<$len> is invalid (under 128, above 256 or not divisible by 32).

In some environments a problem may be encountered that causes the secure random bytes generator to block the program execution (See L<Bytes::Random::Secure/"BLOCKING ENTROPY SOURCE">). In this case you can use I<mnemonic_from_entropy> and pass in entropy generated by L<Bytes::Random::Secure> in non-blocking mode (via the OO interface).

=head2 mnemonic_from_entropy

	$mnemonic = $class->mnemonic_from_entropy($bytes, $lang = "en")

Generates a new mnemonic code from custom entropy given in C<$bytes> (a bytestring). This entropy should be of the same bit size as in L</"generate_mnemonic">. Returns newly generated BIP39 mnemonic string.

This can be useful to avoid relying on the underlying implementation of L<Bitcoin::BIP39>.

Another use would be implementing one's own entropy source that can be truly random, not just cryptographically-secure. A popular example would be capturing user's mouse movements.

Be aware that the method you use to generate a mnemonic will be a very important factor in your key's security. If possible, use real sources of randomness (not pseudo-random) or a cryptographically secure pseduo-random number generator like the one used by L<Bytes::Random::Secure>.

=head2 from_mnemonic

	$key_object = $class->from_mnemonic($mnemonic, $password = "", $lang = undef)

Creates a new key from given mnemonic and password.

Note that technically any password is correct and there's no way to tell if it was mistaken.

If you need to validate if C<$mnemonic> is a valid mnemonic you should specify C<$lang>, e.g. "en".

If no C<$lang> is given then any string passed as C<$mnemonic> will produce a valid key.

Returns a new instance of this class.

B<Important note about unicode:> this function only accepts UTF8-decoded strings (both C<$mnemonic> and C<$password>), but can't detect whether it got it or not. This will only become a problem if you use non-ascii mnemonic and/or password. If there's a possibility of non-ascii, always use utf8 and set binmodes to get decoded (wide) characters to avoid problems recovering your wallet.

=head2 from_seed

	$key_object = $class->from_seed($seed)

Creates and returns a new key from seed, which can be any data of any length. C<$seed> is expected to be a byte string.

=head2 from_hex_seed

	$key_object = $class->from_hex_seed($seed)

Same as C<from_seed>, but C<$seed> is treated as hex string.

=head2 to_serialized

	$serialized = $object->to_serialized()

Returns the key serialized in format specified in BIP32 as byte string.

=head2 to_serialized_base58

	$serialized_base58 = $object->to_serialized_base58()

Behaves the same as C<to_serialized>, but performs Base58Check encoding on the resulting byte string.

=head2 from_serialized

	$key_object = $class->from_serialized($serialized, $network = undef)

Tries to unserialize byte string C<$serialized> with format specified in BIP32.

Dies on errors. If multiple networks match serialized data specify C<$network> manually (id of the network) to avoid exception.

=head2 from_serialized_base58

	$key_object = $class->from_serialized_base58($base58, $network = undef)

Same as C<from_serialized>, but performs Base58Check decoding on C<$base58> argument.

=head2 set_network

	$key_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in L<Bitcoin::Crypto::Network> package or an instance of this class.

Returns current key instance.

=head2 get_public_key

	$public_key_object = $object->get_public_key()

Returns instance of L<Bitcoin::Crypto::Key::ExtPublic> generated from the private key.

=head2 get_basic_key

	$basic_key_object = $object->get_basic_key()

Returns the key in basic format: L<Bitcoin::Crypto::Key::Private>

=head2 derive_key

	$derived_key_object = $object->derive_key($path)

Performs extended key derivation as specified in BIP32 on the current key with C<$path>. Dies on error.

See BIP32 document for details on derivation paths and methods.

Returns a new extended key instance - result of a derivation.

=head2 derive_key_bip44

	$derived_key_object = $object->derive_key_bip44(%data)

A helper that constructs a L<Bitcoin::Crypto::BIP44> path from C<%data> and calls L</derive_key> with it. Refer to L<Bitcoin::Crypto::BIP44/PROPERTIES> to see what you can include in C<%data>.

I<Note: coin_type parameter will be ignored, and the current network configuration set in the extended key will be used.>

=head2 get_fingerprint

	$fingerprint = $object->get_fingerprint($len = 4)

Returns a fingerprint of the extended key of C<$len> length (byte string)

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
