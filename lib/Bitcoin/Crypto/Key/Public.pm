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
use Bitcoin::Crypto::Util qw(hash160 get_public_key_compressed tagged_hash);
use Bitcoin::Crypto::Helpers qw(ecc);

use namespace::clean;

extends qw(Bitcoin::Crypto::Key::Base);

has extended 'key_instance' => (
	required => 0,
	predicate => 1,
);

has field 'taproot_key_instance' => (
	isa => ByteStr,
	lazy => 1,
	writer => -hidden,
	predicate => 1,
);

sub _is_private { 0 }

sub _validate_key
{
	my ($self) = @_;
	if ($self->has_key_instance) {
		$self->SUPER::_validate_key;
	}
	elsif (!$self->has_taproot_key_instance) {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'public key must have either regular or taproot key data'
		);
	}
}

sub _build_taproot_key_instance
{
	my ($self) = @_;

	return substr $self->raw_key('public_compressed'), 1;
}

signature_for raw_key => (
	method => Object,
	positional => [Maybe [Enum [qw(public public_compressed public_taproot)]], {default => undef}],
);

sub raw_key
{
	my ($self, $type) = @_;

	if ($type && $type eq 'public_taproot') {
		return $self->taproot_key_instance;
	}

	return $self->SUPER::raw_key($type);
}

signature_for get_hash => (
	method => Object,
	positional => [],
);

sub get_hash
{
	my ($self) = @_;

	return hash160($self->to_serialized);
}

sub key_hash
{
	my $self = shift;
	my $class = ref $self;

	carp "$class->key_hash() is now deprecated. Use $class->get_hash() instead";
	return $self->get_hash(@_);
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
	positional => [PositiveOrZeroInt, {default => 0}],
);

sub witness_program
{
	state $data_sources = {
		+Bitcoin::Crypto::Constants::segwit_witness_version => sub {
			shift->get_hash;
		},
		+Bitcoin::Crypto::Constants::taproot_witness_version => sub {
			my $self = shift;
			my $internal = $self->raw_key('public_taproot');
			my $tweaked = tagged_hash($internal, 'TapTweak');
			my $combined = ecc->combine_public_keys(ecc->create_public_key($tweaked), "\02" . $internal);
			return substr $combined, 1;
		},
	};

	my ($self, $version) = @_;

	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		"can't get witness program data for version $version"
	) unless exists $data_sources->{$version};

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program
		->add_operation("OP_$version")
		->push_bytes($data_sources->{$version}->($self));

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
	positional => [],
);

sub get_taproot_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	Bitcoin::Crypto::Exception::AddressGenerate->raise(
		'taproot addresses can only be created with BIP44 in taproot (BIP86) mode'
	) unless $self->has_purpose(Bitcoin::Crypto::Constants::bip44_taproot_purpose);

	my $taproot_program = $self->witness_program(Bitcoin::Crypto::Constants::taproot_witness_version);
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

=head2 from_bytes

Deprecated. Use C<< $class->from_serialized($data) >> instead.

=head2 to_bytes

Deprecated. Use C<< $key->to_serialized() >> instead.

=head2 from_hex

Deprecated. Use C<< $class->from_serialized([hex => $data]) >> instead.

=head2 to_hex

Deprecated. Use C<< to_format [hex => $key->to_serialized()] >> instead.

=head2 get_hash

	$bytestr = $object->get_hash()

Returns hash160 of the serialized public key.

=head2 key_hash

Deprecated. Use C<< $key->get_hash() >> instead.

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

Returns string containing Bech32 encoded witness program (C<p2wpkh> address)

If the public key was obtained through BIP44 derivation scheme, this method
will check whether the purpose was C<84> and raise an exception otherwise. If
you wish to generate this address anyway, call L</clear_purpose>.

=head2 get_address

	$address_string = $object->get_address()

Returns a string containing the address. Tries to guess which address type is
most fitting:

=over

=item * If the key has a BIP44 purpose set, generates type of address which
matches the purpose

=item * If the key doesn't have a purpose but the network supports segwit,
returns a segwit address (same as C<get_segwit_address>)

=item * If the network doesn't support segwit, returns legacy address

=back

B<NOTE>: The rules this function uses to choose the address type B<will>
change when more up-to-date address types are implemented (like taproot). Use
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

