package Bitcoin::Crypto::Role::Key;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Util qw(get_key_type);
use Bitcoin::Crypto::Helpers qw(ensure_length ecc);
use Bitcoin::Crypto::Exception;

use Moo::Role;

has param 'key_instance' => (
	isa => ByteStr,
);

has param 'purpose' => (
	isa => BIP44Purpose,
	writer => 1,
	clearer => 1,
	required => 0,
);

with qw(Bitcoin::Crypto::Role::Network);

requires qw(
	_is_private
);

sub BUILD
{
	my ($self) = @_;
	my $entropy = $self->key_instance;

	my $is_private = get_key_type $entropy;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'trying to create key from unknown key data'
	) unless $is_private == $self->_is_private;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'invalid entropy data passed to key creation method'
	) unless defined $is_private;

	if ($is_private) {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'private key is not valid'
		) unless ecc->verify_private_key(ensure_length $entropy, Bitcoin::Crypto::Constants::key_max_length);
	}
}

signature_for has_purpose => (
	method => Object,
	positional => [BIP44Purpose],
);

sub has_purpose
{
	my ($self, $purpose) = @_;

	return !$self->purpose || $self->purpose == $purpose;
}

signature_for raw_key => (
	method => Object,
	positional => [Maybe [Enum [qw(private public public_compressed)]], {default => undef}],
);

# helpers for raw_key
sub __full_private
{
	my ($self, $key) = @_;
	return ensure_length $key, Bitcoin::Crypto::Constants::key_max_length;
}

sub __private_to_public
{
	my ($self, $key) = @_;
	return ecc->create_public_key($self->__full_private($key));
}

sub __public_compressed
{
	my ($self, $key, $compressed) = @_;
	return ecc->compress_public_key($key, $compressed);
}

sub raw_key
{
	my ($self, $type) = @_;
	my $is_private = $self->_is_private;

	$type //= $is_private ? 'private' : 'public';
	if ($type eq 'public' && (!$self->does('Bitcoin::Crypto::Role::Compressed') || $self->compressed)) {
		$type = 'public_compressed';
	}

	if ($type eq 'private') {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'cannot create private key from a public key'
		) unless $is_private;

		return $self->__full_private($self->key_instance);
	}
	else {
		my $key = $self->key_instance;
		$key = $self->__private_to_public($key)
			if $is_private;

		return $self->__public_compressed($key, $type eq 'public_compressed');
	}

	# no need to check for invalid input, since we have a signature with enum
}

1;

