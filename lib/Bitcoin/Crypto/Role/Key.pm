package Bitcoin::Crypto::Role::Key;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;
use Types::Common -sigs;
use Feature::Compat::Try;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Constants qw(:key);
use Bitcoin::Crypto::Util::Internal qw(get_key_type);
use Bitcoin::Crypto::Helpers qw(ensure_length ecc);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Secret;

# ByteStr or BitcoinSecret or SecretBuffer
has param '_key_instance' => (
	writer => 1,
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

sub _run_with_key
{
	my ($self, $sub_ref) = @_;

	if ($self->_is_private) {
		return $self->_key_instance->unmask_to($sub_ref);
	}
	else {
		return $sub_ref->($self->_key_instance);
	}
}

sub _validate_key
{
	state $sig = signature(method => !!1, positional => [ByteStr]);
	my ($self, $entropy) = $sig->(@_);
	my $is_private = get_key_type $entropy;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'invalid entropy data passed to key creation method'
	) unless defined $is_private;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'trying to create key from unknown key data'
	) unless $is_private == $self->_is_private;

	if ($is_private) {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'private key is not valid'
		) unless ecc->verify_private_key(ensure_length $entropy, KEY_MAX_LENGTH);
	}
	else {
		try {

			# keep public keys in compressed form always
			$self->_set_key_instance(ecc->compress_public_key($entropy));
		}
		catch ($e) {
			Bitcoin::Crypto::Exception::KeyCreate->raise(
				'public key is not valid'
			);
		}
	}
}

sub BUILD
{
	my ($self) = @_;
	state $type_secret = BitcoinSecret;

	$self->_set_key_instance($type_secret->assert_coerce($self->_key_instance))
		if $self->_is_private;

	$self->_run_with_key(
		sub {
			$self->_validate_key($_[0]);
		}
	);
}

signature_for has_purpose => (
	method => !!1,
	positional => [BIP44Purpose],
);

sub has_purpose
{
	my ($self, $purpose) = @_;

	return !$self->purpose || $self->purpose == $purpose;
}

signature_for raw_key => (
	method => !!1,
	positional => [Maybe [Enum [qw(private public public_compressed public_xonly)]], {default => undef}],
);

# helpers for raw_key
sub __full_private
{
	state $sig = signature(positional => [ByteStr]);
	my ($key) = $sig->(@_);
	return ensure_length $key, KEY_MAX_LENGTH;
}

sub __private_to_public
{
	my ($key) = @_;
	return ecc->create_public_key(__full_private($key));
}

sub raw_key
{
	my ($self, $type) = @_;
	my $is_private = $self->_is_private;

	$type //= $is_private ? 'private' : 'public';
	if ($type eq 'public' && (!$self->can('compressed') || $self->compressed)) {
		$type = 'public_compressed';
	}

	if ($type eq 'private') {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'cannot create private key from a public key'
		) unless $is_private;

		# CAUTION: exposing the secret!
		return $self->_run_with_key(\&__full_private);
	}
	else {
		my $key = $is_private ? $self->_run_with_key(\&__private_to_public) : $self->_key_instance;
		if ($type eq 'public_xonly') {
			return ecc->xonly_public_key($key);
		}
		else {
			return $key if $type eq 'public_compressed';
			return ecc->compress_public_key($key, !!0);
		}
	}
}

1;

