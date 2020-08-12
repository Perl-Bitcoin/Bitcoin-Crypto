package Bitcoin::Crypto::Key::ExtPublic;

use v5.10; use warnings;
use Moo;
use Crypt::Mac::HMAC qw(hmac);
use Math::EllipticCurve::Prime;
use Math::EllipticCurve::Prime::Point;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(new_bigint ensure_length);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto;

use namespace::clean;
our $VERSION = Bitcoin::Crypto->VERSION;

with "Bitcoin::Crypto::Role::ExtendedKey";

sub _is_private { 0 }

sub _derive_key_partial
{
	my ($self, $child_num, $hardened) = @_;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"cannot derive hardened key from public key"
	) if $hardened;

	# public key data - SEC compressed form
	my $hmac_data = $self->raw_key("public_compressed");

	# child number - 4 bytes
	$hmac_data .= ensure_length pack("N", $child_num), 4;

	my $data = hmac("SHA512", $self->chain_code, $hmac_data);
	my $chain_code = substr $data, 32, 32;

	my $el_curve = Math::EllipticCurve::Prime->from_name($config{curve_name});
	my $number = new_bigint(substr $data, 0, 32);
	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"key $child_num in sequence was found invalid"
	) if $number->bge($el_curve->n);

	my $key = $self->_create_key(substr $data, 0, 32);
	my $point = Math::EllipticCurve::Prime::Point->from_bytes($key->export_key_raw("public"));
	$point->curve($el_curve);
	my $parent_point = Math::EllipticCurve::Prime::Point->from_bytes($self->raw_key("public"));
	$parent_point->curve($el_curve);
	$point->badd($parent_point);

	return (blessed $self)->new(
		$point->to_bytes,
		$chain_code,
		$child_num,
		$self->get_fingerprint,
		$self->depth + 1
	);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::ExtPublic - class for Bitcoin extended public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::ExtPrivate;

	my $mnemonic = Bitcoin::Crypto::Key::ExtPrivate->generate_mnemonic;
	my $key = Bitcoin::Crypto::Key::ExtPrivate->from_mnemonic($mnemonic);

	# derive child public key
	my $path = "M/0";
	my $child_key = $key->derive_key($path);
	my $ser_child_key = $child_key->to_serialized_base58;
	print "Your exported $path child key is: $ser_child_key";

	# create basic public key
	my $basic_public = $child_key->get_basic_key;

=head1 DESCRIPTION

This class allows you to create an extended public key instance.

You can use an extended public key to:

=over 2

=item * derive extended keys using a path (only public keys)

=item * restore keys from serialized base58 format

=back

see L<Bitcoin::Crypto::Network> if you want to work with other networks than Bitcoin Mainnet.

=head1 METHODS

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

=head2 get_basic_key

	sig: get_basic_key($self)

Returns the key in basic format: L<Bitcoin::Crypto::Key::Public>

=head2 derive_key

	sig: derive_key($self, $path)

Performs extended key derivation as specified in BIP32 on the current key with $path. Dies on error.

See BIP32 document for details on derivation paths and methods.

Note that public keys cannot derive private keys and your derivation path must start with M (capital m).

Returns a new extended key instance - result of a derivation.

=head2 get_fingerprint

	sig: get_fingerprint($self, $len = 4)

Returns a fingerprint of the extended key of $len length (byte string)

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * KeyDerive - key couldn't be derived correctly

=item * KeyCreate - key couldn't be created correctly

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=item L<Bitcoin::Crypto::Network>

=back

=cut
