package Bitcoin::Crypto::Key::Public;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use Carp qw(carp);

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Util qw(hash160 get_public_key_compressed);
use Bitcoin::Crypto::Helpers qw(ecc);

use namespace::clean;

extends qw(Bitcoin::Crypto::Key::Base);

sub _is_private { 0 }

signature_for get_hash => (
	method => Object,
	positional => [],
);

sub get_hash
{
	my ($self) = @_;

	return hash160($self->to_serialized);
}

signature_for get_xonly_key => (
	method => Object,
	positional => [],
);

sub get_xonly_key
{
	my ($self) = @_;

	return $self->raw_key('public_xonly');
}

signature_for from_serialized => (
	method => Str,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $key) = @_;

	my $self = $class->SUPER::from_serialized($key);
	$self->set_compressed(get_public_key_compressed($key));

	return $self;
}

signature_for witness_program => (
	method => Object,
	positional => [PositiveOrZeroInt, {default => 0}, HashRef, {default => sub { {} }}],
);

sub witness_program
{
	state $data_sources = {
		(Bitcoin::Crypto::Constants::segwit_witness_version) => sub {
			return shift->get_hash;
		},
		(Bitcoin::Crypto::Constants::taproot_witness_version) => sub {
			my ($self, $params) = @_;

			$self = $self->get_taproot_output_key($params->{tweak_suffix})
				unless $self->taproot_output;

			return $self->get_xonly_key;
		},
	};

	my ($self, $version, $source_data) = @_;

	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		"can't get witness program data for version $version"
	) unless exists $data_sources->{$version};

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program
		->add_operation("OP_$version")
		->push_bytes($data_sources->{$version}->($self, $source_data));

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

	my $pkh = $self->network->p2pkh_byte . $self->get_hash;
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

	return encode_segwit($self->network->segwit_hrp, $self->witness_program->run->stack_serialized);
}

signature_for get_taproot_address => (
	method => Object,
	positional => [Maybe [BitcoinScriptTree], {default => undef}],
);

sub get_taproot_address
{
	my ($self, $script_tree) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	Bitcoin::Crypto::Exception::AddressGenerate->raise(
		'taproot addresses can only be created with BIP44 in taproot (BIP86) mode'
	) unless $self->has_purpose(Bitcoin::Crypto::Constants::bip44_taproot_purpose);

	my $taproot_program = $self->witness_program(
		Bitcoin::Crypto::Constants::taproot_witness_version,
		defined $script_tree ? {tweak_suffix => $script_tree->get_merkle_root} : {}
	);

	return encode_segwit($self->network->segwit_hrp, $taproot_program->run->stack_serialized);
}

signature_for get_address => (
	method => Object,
	positional => [],
);

sub get_address
{
	my ($self) = @_;

	return $self->get_taproot_address
		if $self->has_purpose(Bitcoin::Crypto::Constants::bip44_taproot_purpose);

	return $self->get_segwit_address
		if $self->has_purpose(Bitcoin::Crypto::Constants::bip44_segwit_purpose);

	return $self->get_compat_address
		if $self->has_purpose(Bitcoin::Crypto::Constants::bip44_compat_purpose);

	return $self->get_legacy_address
		if $self->has_purpose(Bitcoin::Crypto::Constants::bip44_purpose);

	return $self->get_taproot_address
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

	# verify signature of custom message
	# (it has to be byte string, see perlpacktut)

	$pub->verify_message('Hello world', $sig);

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

=head2 get_hash

	$bytestr = $object->get_hash()

Returns hash160 of the serialized public key.

=head2 set_compressed

	$object->set_compressed($val)

Change key's compression state to C<$val> (boolean). This will change the
address.

=head2 set_network

	$object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in
L<Bitcoin::Crypto::Network> package or an instance of this class.

=head2 witness_program

	$script = $object->witness_program($version, \%args = {})

Returns a witness program for given witness C<$version> as
L<Bitcoin::Crypto::Script> instance. C<%args> depends on witness version:

=over

=item

For witness version 0 (segwit), no arguments are used.

=item

For witness version 1 (taproot), C<tweak_suffix> optional bytestring argument
can be passed.

=back

=head2 get_taproot_output_key

	$pub = $object->get_taproot_output_key($tweak_suffix = undef)

Returns a new public key instance that represents an output taproot key.
Optional C<$tweak_suffix> can be passed as bytestring.

=head2 get_xonly_key

	$bytestring = $object->get_xonly_key()

Returns a 32-byte bytestring containing the xonly key for this public key.

=head2 verify_message

	$signature_valid = $object->verify_message($message, $signature)

Verifies C<$signature> against digest of C<$message> (digesting it with double
sha256) using public key.

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

Returns a string containing Bech32 encoded witness version 0 program (C<p2wpkh>
address)

If the public key was obtained through BIP44 derivation scheme, this method
will check whether the purpose was C<84> and raise an exception otherwise. If
you wish to generate this address anyway, call L</clear_purpose>.

=head2 get_taproot_address

	$address_string = $object->get_taproot_address($script_tree = undef)

Returns a string containing Bech32m encoded witness version 1 program (C<p2tr>
address)

Optional C<$script_tree> can be passed as L<Bitcoin::Crypto::Script::Tree>
object. Passing this argument will generate an address that can be spent using
script path spend as well as key path spend.

If the public key was obtained through BIP44 derivation scheme, this method
will check whether the purpose was C<86> and raise an exception otherwise. If
you wish to generate this address anyway, call L</clear_purpose>.

=head2 get_address

	$address_string = $object->get_address()

Returns a string containing the address. Tries to guess which address type is
most fitting:

=over

=item * If the key has a BIP44 purpose set, generates type of address which
matches the purpose

=item * If the key doesn't have a purpose but the network supports segwit,
returns a taproot address (same as C<get_taproot_address>, but does not accept
a script tree)

=item * If the network doesn't support segwit, returns legacy address

=back

B<NOTE>: The rules this function uses to choose the address type B<will>
change when more up-to-date address types are implemented. Use
other address functions if this is not what you want.

=head2 clear_purpose

	$object->clear_purpose;

Clears the BIP44 purpose of this key instance, removing safety checks on
address generation.

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

