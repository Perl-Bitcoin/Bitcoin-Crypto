package Bitcoin::Crypto::Key::ExtPublic;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Crypt::Mac::HMAC qw(hmac);
use Types::Common -sigs;

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Helpers qw(ensure_length ecc);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::BIP44;

extends qw(Bitcoin::Crypto::Key::ExtBase);

sub _is_private { 0 }

sub derive_key_bip44
{
	my ($self, %data) = @_;
	my $path = Bitcoin::Crypto::BIP44->new(
		%data,
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
	my $key = $self->raw_key('public_compressed');

	# key + child number - 4 bytes
	my $hmac_data = $key . ensure_length pack('N', $child_num), 4;

	my $data = hmac('SHA512', $self->chain_code, $hmac_data);
	my $tweak = substr $data, 0, 32;
	my $chain_code = substr $data, 32, 32;

	Bitcoin::Crypto::Exception::KeyDerive->trap_into(
		sub {
			$key = ecc->add_public_key($key, $tweak);
		},
		"key $child_num in sequence was found invalid"
	);

	return $self->new(
		_key_instance => $key,
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
	my $key = btc_extprv->from_mnemonic($mnemonic)->get_public_key;

	# derive child public key
	my $path = "M/0";
	my $child_key = $key->derive_key($path);
	my $ser_child_key = to_format [base58 => $child_key->to_serialized];
	print "Your exported $path child key is: $ser_child_key";

	# create basic public key
	my $basic_public = $child_key->get_basic_key;

=head1 DESCRIPTION

This class allows you to create an extended public key instance. They are
public counterparts to extended keys.

You can use an extended public key to:

=over

=item * derive extended keys using a path (only public keys, no hardened paths)

=item * export and restore keys from the serialized format

=back

Extended public keys pose a security risk: if the attacker obtains an extended
public key and a single private key derived from the extended private key
associated with the public key, they can obtain every private key on the same
derivation path. For this reason, it is not recommended to share extended
public keys.

=head1 INTERFACE

=head2 Attributes

=head3 network

Instance of L<Bitcoin::Crypto::Network> - current network for this key. Can be
coerced from network id. Default: current default network.

I<writer:> C<set_network>

=head3 purpose

BIP44 purpose which was used to obtain this key. Filled automatically when
deriving an extended key. If the key was not obtained through BIP44 derivation,
this attribute is C<undef>.

I<writer:> C<set_purpose>

I<clearer:> C<clear_purpose>

=head3 depth

Integer - depth of derivation. Default: C<0> (master key)

=head3 parent_fingerprint

Bytestring of length 4 - fingerprint of the parent key. Default: four zero bytes

=head3 child_number

Integer - sequence number of the key on the current L</depth>. Default: C<0>

=head3 chain_code

Bytestring of length 32 - chain code of the extended key.

=head2 Methods

=head3 new

Constructor is reserved for internal and advanced use only. Use L</from_serialized> instead.

=head3 to_serialized

	$serialized_key = $object->to_serialized()

Returns the key serialized in format specified in BIP32 as byte string.

=head3 from_serialized

	$key_object = $class->from_serialized($serialized, $network = undef)

Tries to unserialize byte string C<$serialized> with format specified in BIP32.

Dies on errors. If multiple networks match serialized data specify C<$network>
manually (id of the network) to avoid exception.

=head3 get_basic_key

	$basic_key_object = $object->get_basic_key()

Returns the key in basic format: L<Bitcoin::Crypto::Key::Public>

=head3 derive_key

	$derived_key_object = $object->derive_key($path)

Performs extended key derivation as specified in BIP32 on the current key with
C<$path>. Dies on error.

See BIP32 document for details on derivation paths and methods.

Note that public keys cannot derive private keys and your derivation path must
start with M (capital m).

Returns a new extended key instance - result of a derivation.

=head3 derive_key_bip44

	$derived_key_object = $object->derive_key_bip44(%data)

A helper that constructs a L<Bitcoin::Crypto::BIP44> path from C<%data> and
calls L</derive_key> with it. In extended public keys, bip44 is always
constructed with C<public> setting - it will always derive starting from
account, effectively only using C<change> and C<index> attributes.

=head3 get_fingerprint

	$fingerprint = $object->get_fingerprint($len = 4)

Returns a fingerprint of the extended key of C<$len> length (byte string)

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=item L<Bitcoin::Crypto::Network>

=back

=cut

