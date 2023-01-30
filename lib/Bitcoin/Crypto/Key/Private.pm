package Bitcoin::Crypto::Key::Private;

use v5.10;
use strict;
use warnings;
use Moo;
use Crypt::PK::ECC;
use Bitcoin::BIP39 qw(bip39_mnemonic_to_entropy entropy_to_bip39_mnemonic);
use List::Util qw(first);
use Type::Params -sigs;

use Bitcoin::Crypto::Key::Public;
use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);
use Bitcoin::Crypto::Types qw(Object ClassName Str Maybe);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Util qw(validate_wif);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Exception;

use namespace::clean;

with qw(Bitcoin::Crypto::Role::BasicKey);

sub _is_private { 1 }

signature_for to_wif => (
	positional => [Object],
);

sub to_wif
{
	my ($self) = @_;
	my $bytes = $self->to_bytes();

	# wif network - 1B
	my $wifdata = $self->network->wif_byte;

	# key entropy - 32B
	$wifdata .= ensure_length $bytes, Bitcoin::Crypto::Constants::key_max_length;

	# additional byte for compressed key - 1B
	$wifdata .= Bitcoin::Crypto::Constants::wif_compressed_byte if $self->compressed;

	return encode_base58check($wifdata);
}

signature_for from_wif => (
	positional => [ClassName, Str, Maybe[Str], { optional => 1 }],
);

sub from_wif
{
	my ($class, $wif, $network) = @_;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'base58 string is not valid WIF'
	) unless validate_wif($wif);

	my $decoded = decode_base58check($wif);
	my $private = substr $decoded, 1;

	my $compressed = 0;
	if (length($private) > Bitcoin::Crypto::Constants::key_max_length) {
		chop $private;
		$compressed = 1;
	}

	my $wif_network_byte = substr $decoded, 0, 1;
	my @found_networks =
		Bitcoin::Crypto::Network->find(sub { shift->wif_byte eq $wif_network_byte });
	@found_networks = first { $_ eq $network }
		@found_networks
		if defined $network;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'found multiple networks possible for given WIF'
	) if @found_networks > 1;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"network name $network cannot be used for given WIF"
	) if @found_networks == 0 && defined $network;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"couldn't find network for WIF byte $wif_network_byte"
	) if @found_networks == 0;

	my $instance = $class->from_bytes($private);
	$instance->set_compressed($compressed);
	$instance->set_network(@found_networks);
	return $instance;
}

signature_for get_public_key => (
	positional => [Object],
);

sub get_public_key
{
	my ($self) = @_;

	my $public = Bitcoin::Crypto::Key::Public->new(
		key_instance => $self->raw_key('public'),
		compressed => $self->compressed,
		network => $self->network,
		purpose => $self->purpose,
	);

	return $public;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::Private - Bitcoin private keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::Private;

	# get Bitcoin::Crypto::Key::Public instance from private key

	my $pub = $priv->get_public_key();

	# create signature using private key (sha256 of string byte representation)

	my $sig = $priv->sign_message('Hello world');

	# signature is returned as byte string
	# use unpack to get the representation you need

	my $sig_hex = unpack 'H*', $sig;

	# signature verification

	$priv->verify_message('Hello world', $sig);

=head1 DESCRIPTION

This class allows you to create a private key instance.

You can use a private key to:

=over 2

=item * generate public keys

=item * sign and verify messages

=back

Please note that any keys generated are by default compressed.

see L<Bitcoin::Crypto::Network> if you want to work with other networks than Bitcoin Mainnet.

=head1 METHODS

=head2 new

Constructor is reserved for internal and advanced use only. Use L</from_bytes>,
L</from_hex> and L</from_wif> instead.

=head2 from_bytes

	$key_object = $class->from_bytes($data)

Use this method to create a PrivateKey instance from a byte string.
Data C<$data> will be used as a private key entropy.

Returns class instance.

=head2 to_bytes

	$bytestring = $object->to_bytes()

Does the opposite of from_bytes on a target object

=head2 from_hex

	$key_object = $class->from_hex($hex)

Use this method to create a PrivateKey instance from a hexadecimal number.
Number C<$hex> will be used as a private key entropy.

Returns class instance.

=head2 to_hex

	$hex_string = $object->to_hex()

Does the opposite of from_hex on a target object

=head2 from_wif

	$key_object = $class->from_wif($str, $network = undef)

Creates a new private key from Wallet Import Format string.

Takes an additional optional argument, which is network name. It may be useful if you use many networks and some have the same WIF byte.

This method will change compression and network states of the created private key, as this data is included in WIF format.

Returns class instance.

=head2 to_wif

	$wif_string = $object->to_wif()

Does the opposite of from_wif on a target object

=head2 set_compressed

	$key_object = $object->set_compressed($val)

Change key's compression state to C<$val> (1/0). This will change the WIF generated by
toWif() method and also enable creation of uncompressed public keys.
If C<$val> is omitted it is set to 1.

Returns current key instance.

=head2 set_network

	$key_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 get_public_key

	$public_key_object = $object->get_public_key()

Returns instance of L<Bitcoin::Crypto::Key::Public> generated from the private key.

=head2 sign_message

	$signature = $object->sign_message($message, $algo = 'sha256')

Signs a digest of C<$message> (using C<$algo> digest algorithm) with a private key.

C<$algo> must be available in L<Digest> package.

Returns a byte string containing signature.

Character encoding note: C<$message> should be encoded in the proper encoding before passing it to this method. Passing Unicode string will cause the function to fail. You can encode like this (for UTF-8):

	use Encode qw(encode);
	$message = encode('UTF-8', $message);

Caution: libtomcrypt cryptographic package that is generating signatures does not currently offer a deterministic mechanism. For this reason the sign_message method will complain with a warning. You should install an optional L<Crypt::Perl> package, which supports deterministic signatures, which will disable the warning. Non-deterministic signatures can lead to leaking private keys if the random number generator's entropy is insufficient.

=head2 verify_message

	$signature_valid = $object->verify_message($message, $signature, $algo = 'sha256')

Verifies C<$signature> against digest of C<$message> (with C<$algo> digest algorithm) using private key.

C<$algo> must be available in Digest package.

Returns boolean.

Character encoding note: C<$message> should be encoded in the proper encoding before passing it to this method. Passing Unicode string will cause the function to fail. You can encode like this (for UTF-8):

	use Encode qw(encode);
	$message = encode('UTF-8', $message);

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * Sign - couldn't sign the message correctly

=item * Verify - couldn't verify the message correctly

=item * KeyCreate - key couldn't be created correctly

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::Public>

=item L<Bitcoin::Crypto::Network>

=back

=cut

