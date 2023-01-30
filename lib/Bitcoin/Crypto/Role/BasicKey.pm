package Bitcoin::Crypto::Role::BasicKey;

use v5.10;
use strict;
use warnings;
use Carp qw(carp);
use Type::Params -sigs;

use Bitcoin::Crypto::Helpers qw(pad_hex verify_bytestring);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Object Str ByteStr);
use Moo::Role;

with qw(
	Bitcoin::Crypto::Role::Key
	Bitcoin::Crypto::Role::Compressed
);

around BUILDARGS => sub {
	my ($orig, $class, @params) = @_;

	if (@params == 1) {
		carp "$class->new(\$bytes) is now deprecated. Use $class->from_bytes(\$bytes) instead";
		unshift @params, 'key_instance';
	}

	return $class->$orig(@params);
};

signature_for sign_message => (
	method => Object,
	positional => [Str, Str, { default => 'sha256' }],
);

sub sign_message
{
	my ($self, $message, $algorithm) = @_;

	Bitcoin::Crypto::Exception::Sign->raise(
		'cannot sign a message with a public key'
	) unless $self->_is_private;

	if (eval { require Crypt::Perl } && Crypt::Perl->VERSION gt '0.33') {
		require Crypt::Perl::ECDSA::Parse;
		$self->{_crypt_perl_prv} = Crypt::Perl::ECDSA::Parse::private($self->key_instance->export_key_der('private'))
			if !exists $self->{_crypt_perl_prv};
	}
	else {
		carp
			'Current implementation of CryptX signature generation does not produce deterministic results. For better security, install the Crypt::Perl module.';
	}

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			if (exists $self->{_crypt_perl_prv}) {
				my $sub = "sign_${algorithm}";
				return $self->{_crypt_perl_prv}->$sub($message);
			}
			else {
				return $self->key_instance->sign_message($message, $algorithm);
			}
		}
	);
}

signature_for verify_message => (
	method => Object,
	positional => [Str, ByteStr, Str, { default => 'sha256' }],
);

sub verify_message
{
	my ($self, $message, $signature, $algorithm) = @_;

	return Bitcoin::Crypto::Exception::Verify->trap_into(
		sub {
			$self->key_instance->verify_message($signature, $message, $algorithm);
		}
	);
}

signature_for from_hex => (
	method => Str,
	positional => [Str],
);

sub from_hex
{
	my ($class, $val) = @_;
	return $class->from_bytes(pack 'H*', pad_hex($val));
}

signature_for to_hex => (
	method => Object,
	positional => [],
);

sub to_hex
{
	my ($self) = @_;
	return unpack 'H*', $self->to_bytes();
}

signature_for from_bytes => (
	method => Str,
	positional => [ByteStr],
);

sub from_bytes
{
	my ($class, $bytes) = @_;

	return $class->new(key_instance => $bytes);
}

signature_for to_bytes => (
	method => Object,
	positional => [],
);

sub to_bytes
{
	my ($self) = @_;
	return $self->raw_key;
}

1;

