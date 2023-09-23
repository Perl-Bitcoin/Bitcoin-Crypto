package Bitcoin::Crypto::Key::Public;

use v5.10;
use strict;
use warnings;
use Moo;
use Type::Params -sigs;

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Types qw(Object);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Util qw(hash160);

use namespace::clean;

with qw(Bitcoin::Crypto::Role::BasicKey);

sub _is_private { 0 }

signature_for key_hash => (
	method => Object,
	positional => [],
);

sub key_hash
{
	my ($self) = @_;

	return hash160($self->to_serialized);
}

signature_for witness_program => (
	method => Object,
	positional => [],
);

sub witness_program
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program
		->add_operation('OP_' . Bitcoin::Crypto::Constants::segwit_witness_version)
		->push_bytes($self->key_hash);

	return $program;
}

signature_for get_legacy_address => (
	method => Object,
	positional => [],
);

sub get_legacy_address
{
	my ($self) = @_;

	Bitcoin::Crypto::Exception::AddressGenerate->raise(
		'legacy addresses can only be created with BIP44 in legacy (BIP44) mode'
	) unless $self->has_purpose(Bitcoin::Crypto::Constants::bip44_purpose);

	my $pkh = $self->network->p2pkh_byte . $self->key_hash;
	return encode_base58check($pkh);
}

signature_for get_compat_address => (
	method => Object,
	positional => [],
);

sub get_compat_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	Bitcoin::Crypto::Exception::AddressGenerate->raise(
		'compat addresses can only be created with BIP44 in compat (BIP49) mode'
	) unless $self->has_purpose(Bitcoin::Crypto::Constants::bip44_compat_purpose);

	return $self->witness_program->get_legacy_address;
}

signature_for get_segwit_address => (
	method => Object,
	positional => [],
);

sub get_segwit_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	Bitcoin::Crypto::Exception::AddressGenerate->raise(
		'segwit addresses can only be created with BIP44 in segwit (BIP84) mode'
	) unless $self->has_purpose(Bitcoin::Crypto::Constants::bip44_segwit_purpose);

	return encode_segwit($self->network->segwit_hrp, join '', @{$self->witness_program->run->stack});
}

signature_for get_address => (
	method => Object,
	positional => [],
);

sub get_address
{
	my ($self) = @_;

	return $self->get_segwit_address
		if $self->has_purpose(Bitcoin::Crypto::Constants::bip44_segwit_purpose);

	return $self->get_compat_address
		if $self->has_purpose(Bitcoin::Crypto::Constants::bip44_compat_purpose);

	return $self->get_legacy_address
		if $self->has_purpose(Bitcoin::Crypto::Constants::bip44_purpose);

	return $self->get_segwit_address
		if $self->network->supports_segwit;

	return $self->get_legacy_address;
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Key::Public - Bitcoin public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::Public;

	$pub = Bitcoin::Crypto::Key::Public->from_serialized([hex => $asn_hex]);

	# verify signature (it has to be byte string, see perlpacktut)

	$pub->verify_message(pack('a*', 'Hello world'), $sig);

	# getting address from public key (p2wpkh)

	my $address = $pub->get_segwit_address();

=head1 DESCRIPTION

This class allows you to create a public key instance.

You can use a public key to:

=over

=item * verify messages

=item * create addresses: legacy (p2pkh), compatibility (p2sh(p2wpkh)) and segwit (p2wpkh).

=back

=head1 METHODS

=head2 new

Constructor is reserved for internal and advanced use only. Use L</from_serialized>
instead.

=head2 from_serialized

	$key_object = $class->from_serialized($serialized)

This creates a new key from string data. Argument C<$serialized> is a
formatable bytestring which must represent a public key in ASN X9.62 format.

Returns a new key object instance.

=head2 to_serialized

	$serialized = $key_object->to_serialized()

This returns a public key in ASN X9.62 format. The result is a bytestring which
can be further formated with C<to_format> utility.

The result will vary depending on compression state: see L</set_compressed>

=head2 from_bytes

Deprecated. Use C<< $class->from_serialized($data) >> instead.

=head2 to_bytes

Deprecated. Use C<< $key->to_serialized($data) >> instead.

=head2 from_hex

Deprecated. Use C<< $class->from_serialized([hex => $data]) >> instead.

=head2 to_hex

Deprecated. Use C<< to_format [hex => $key->to_serialized($data)] >> instead.

=head2 set_compressed

	$key_object = $object->set_compressed($val)

Change key's compression state to C<$val> (boolean). This will change the
address. If C<$val> is omitted it is set to C<1>.

Returns current key instance.

=head2 set_network

	$key_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in
L<Bitcoin::Crypto::Network> package or an instance of this class.

Returns current key instance.

=head2 verify_message

	$signature_valid = $object->verify_message($message, $signature)

Verifies C<$signature> against digest of C<$message> (digesting it with double sha256) using public key.

Returns boolean.

Character encoding note: C<$message> should be encoded in the proper encoding
before passing it to this method. Passing Unicode string will cause the
function to fail. You can encode like this (for UTF-8):

	use Encode qw(encode);
	$message = encode('UTF-8', $message);

=head2 get_legacy_address

	$address_string = $object->get_legacy_address()

Returns string containing Base58Check encoded public key hash (C<p2pkh> address).

If the public key was obtained through BIP44 derivation scheme, this method
will check whether the purpose was C<44> and raise an exception otherwise. If
you wish to generate this address anyway, call L</clear_purpose>.

=head2 get_compat_address

	$address_string = $object->get_compat_address()

Returns string containing Base58Check encoded script hash containing a witness
program for compatibility purposes (C<p2sh(p2wpkh)> address)

If the public key was obtained through BIP44 derivation scheme, this method
will check whether the purpose was C<49> and raise an exception otherwise. If
you wish to generate this address anyway, call L</clear_purpose>.

=head2 get_segwit_address

	$address_string = $object->get_segwit_address()

Returns string containing Bech32 encoded witness program (C<p2wpkh> address)

If the public key was obtained through BIP44 derivation scheme, this method
will check whether the purpose was C<84> and raise an exception otherwise. If
you wish to generate this address anyway, call L</clear_purpose>.

=head2 get_address

	$address_string = $object->get_address()

Returns a string containing the address. Tries to guess which address type most
fitting:

=over

=item * If the key has a set purpose, generates type of address which matches
the purpose

=item * If the key doesn't have a purpose but the network supports segwit,
returns segwit address

=item * If the network doesn't support segwit, returns legacy address

=back

B<NOTE>: The rules this functions uses to choose the address type B<will>
change when more up-to-date address types are implemented (like taproot). Use
other address functions if this is not what you want.

=head2 clear_purpose

	$object->clear_purpose;

Clears the purpose of this key instance, removing safety checks on address
generation.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * KeyCreate - key couldn't be created correctly

=item * Verify - couldn't verify the message correctly

=item * NetworkConfig - incomplete or corrupted network configuration

=item * AddressGenerate - address could not be generated (see BIP44 constraint notes)

=back

=head1 SEE ALSO

L<Bitcoin::Crypto::Key::Private>

L<Bitcoin::Crypto::Base58>

L<Bitcoin::Crypto::Bech32>

