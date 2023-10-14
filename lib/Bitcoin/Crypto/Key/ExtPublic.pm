package Bitcoin::Crypto::Key::ExtPublic;

use v5.10;
use strict;
use warnings;
use Moo;
use Crypt::Mac::HMAC qw(hmac);
use Type::Params -sigs;

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Helpers qw(ensure_length add_ec_points);
use Bitcoin::Crypto::Types qw(Object HashRef);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::BIP44;

use namespace::clean;

with qw(Bitcoin::Crypto::Role::ExtendedKey);

sub _is_private { 0 }

signature_for derive_key_bip44 => (
	method => Object,
	positional => [HashRef, {slurpy => 1}],
);

sub derive_key_bip44
{
	my ($self, $data) = @_;
	my $path = Bitcoin::Crypto::BIP44->new(
		%{$data},
		coin_type => $self,
		public => 1,
	);

	return $self->derive_key($path);
}

sub _derive_key_partial
{
	my ($self, $child_num, $hardened) = @_;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		'cannot derive hardened key from public key'
	) if $hardened;

	# public key data - SEC compressed form
	my $hmac_data = $self->raw_key('public_compressed');

	# child number - 4 bytes
	$hmac_data .= ensure_length pack('N', $child_num), 4;

	my $data = hmac('SHA512', $self->chain_code, $hmac_data);
	my $chain_code = substr $data, 32, 32;

	my $n_order = Math::BigInt->from_hex($self->key_instance->curve2hash->{order});
	my $number = Math::BigInt->from_bytes(substr $data, 0, 32);
	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"key $child_num in sequence was found invalid"
	) if $number->bge($n_order);

	my $key = $self->_create_key(substr $data, 0, 32);
	my $point = $key->export_key_raw('public');
	my $parent_point = $self->raw_key('public');
	$point = add_ec_points($point, $parent_point);

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"key $child_num in sequence was found invalid"
	) unless defined $point;

	return $self->new(
		key_instance => $point,
		chain_code => $chain_code,
		child_number => $child_num,
		parent_fingerprint => $self->get_fingerprint,
		depth => $self->depth + 1,
	);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::ExtPublic - Bitcoin extended public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_extprv);
	use Bitcoin::Crypto::Util qw(generate_mnemonic to_format)

	my $mnemonic = generate_mnemonic;
	my $key = btc_extprv->from_mnemonic($mnemonic);

	# derive child public key
	my $path = "M/0";
	my $child_key = $key->derive_key($path);
	my $ser_child_key = to_format [base58 => $child_key->to_serialized];
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

=head2 new

Constructor is reserved for internal and advanced use only. Use L</from_serialized> instead.

=head2 to_serialized

	$serialized_key = $object->to_serialized()

Returns the key serialized in format specified in BIP32 as byte string.

=head2 to_serialized_base58

Deprecated. Use C<< to_format [base58 => $key->to_serialized] >> instead.

=head2 from_serialized

	$key_object = $class->from_serialized($serialized, $network = undef)

Tries to unserialize byte string C<$serialized> with format specified in BIP32.

Dies on errors. If multiple networks match serialized data specify C<$network>
manually (id of the network) to avoid exception.

=head2 from_serialized_base58

Deprecated. Use C<< $class->from_serialized([base58 => $base58]) >> instead.

=head2 set_network

	$key_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in
Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 get_basic_key

	$basic_key_object = $object->get_basic_key()

Returns the key in basic format: L<Bitcoin::Crypto::Key::Public>

=head2 derive_key

	$derived_key_object = $object->derive_key($path)

Performs extended key derivation as specified in BIP32 on the current key with
C<$path>. Dies on error.

See BIP32 document for details on derivation paths and methods.

Note that public keys cannot derive private keys and your derivation path must
start with M (capital m).

Returns a new extended key instance - result of a derivation.

=head2 derive_key_bip44

	$derived_key_object = $object->derive_key_bip44(%data)

A helper that constructs a L<Bitcoin::Crypto::BIP44> path from C<%data> and
calls L</derive_key> with it. In extended public keys, bip44 is always
constructed with C<public> setting - it will always derive starting from
account, effectively only using C<change> and C<index> attributes.

=head2 get_fingerprint

	$fingerprint = $object->get_fingerprint($len = 4)

Returns a fingerprint of the extended key of C<$len> length (byte string)

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

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

