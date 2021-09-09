package Bitcoin::Crypto::Key::ExtPublic;

our $VERSION = "1.001";

use v5.10;
use warnings;
use Moo;
use Crypt::Mac::HMAC qw(hmac);
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(new_bigint ensure_length add_ec_points);
use Bitcoin::Crypto::Exception;

use namespace::clean;

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

	my $n_order = new_bigint(pack "H*", $self->key_instance->curve2hash->{order});
	my $number = new_bigint(substr $data, 0, 32);
	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"key $child_num in sequence was found invalid"
	) if $number->bge($n_order);

	my $key = $self->_create_key(substr $data, 0, 32);
	my $point = $key->export_key_raw("public");
	my $parent_point = $self->raw_key("public");
	$point = add_ec_points($point, $parent_point);

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"key $child_num in sequence was found invalid"
	) unless defined $point;

	return (blessed $self)->new(
		$point,
		$chain_code,
		$child_num,
		$self->get_fingerprint,
		$self->depth + 1
	);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::ExtPublic - Bitcoin extended public keys

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

	$serialized_key = $object->to_serialized()

Returns the key serialized in format specified in BIP32 as byte string.

=head2 to_serialized_base58

	$serialized_key = $object->to_serialized_base58()

Behaves the same as to_serialized(), but performs Base58Check encoding on the resulting byte string.

=head2 from_serialized

	$key_object = $class->from_serialized($serialized, $network = undef)

Tries to unserialize byte string C<$serialized> with format specified in BIP32.

Dies on errors. If multiple networks match serialized data specify C<$network> manually (id of the network) to avoid exception.

=head2 from_serialized_base58

	$key_object = $class->from_serialized_base58($base58, $network = undef)

Same as from_serialized, but performs Base58Check decoding on C<$base58> argument.

=head2 set_network

	$key_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 get_basic_key

	$basic_key_object = $object->get_basic_key()

Returns the key in basic format: L<Bitcoin::Crypto::Key::Public>

=head2 derive_key

	$derived_key_object = $object->derive_key($path)

Performs extended key derivation as specified in BIP32 on the current key with C<$path>. Dies on error.

See BIP32 document for details on derivation paths and methods.

Note that public keys cannot derive private keys and your derivation path must start with M (capital m).

Returns a new extended key instance - result of a derivation.

=head2 get_fingerprint

	$fingerprint = $object->get_fingerprint($len = 4)

Returns a fingerprint of the extended key of C<$len> length (byte string)

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
