package Bitcoin::Crypto::Role::DSA;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Carp qw(carp);
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Object Str ByteStr InstanceOf);
use Moo::Role;

use constant HAS_DETERMINISTIC_SIGNATURES => eval { require Crypt::Perl } && Crypt::Perl->VERSION gt '0.33';

requires qw(
	key_instance
	_is_private
);

has field '_crypt_perl_prv' => (
	isa => InstanceOf['Crypt::Perl::ECDSA::PrivateKey'],
	lazy => sub {
		require Crypt::Perl::ECDSA::Parse;
		return Crypt::Perl::ECDSA::Parse::private($_[0]->key_instance->export_key_der('private'))
	}
);

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

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			if (HAS_DETERMINISTIC_SIGNATURES) {
				my $sub = "sign_${algorithm}";
				return $self->_crypt_perl_prv->$sub($message);
			}
			else {
				carp 'Current implementation of CryptX signature generation does not produce deterministic results. For better security, install the Crypt::Perl module.';
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

1;

