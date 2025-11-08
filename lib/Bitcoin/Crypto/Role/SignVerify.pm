package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use Try::Tiny;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Helpers qw(ecc);
use Bitcoin::Crypto::Transaction::Sign;
use Bitcoin::Crypto::Constants;
use Moo::Role;

requires qw(
	raw_key
	taproot_output
	_is_private
);

my %algorithms = (
	default => {
		signing_method => sub {
			my ($key, $digest) = @_;

			return ecc->sign_digest($key->raw_key, $digest);
		},
		verification_method => sub {
			my ($key, $signature, $digest) = @_;

			# high-S is a standardness rule, not a protocol rule
			# my $normalized = ecc->normalize_signature($signature);
			# return !!0 if $normalized ne $signature;
			return ecc->verify_digest($key->raw_key('public'), $signature, $digest);
		},
	},
	schnorr => {
		signing_method => sub {
			my ($key, $digest) = @_;

			return ecc->sign_digest_schnorr($key->raw_key, $digest);
		},
		verification_method => sub {
			my ($key, $signature, $digest) = @_;

			return ecc->verify_digest_schnorr($key->raw_key('public_xonly'), $signature, $digest);
		},
	},
);

signature_for sign_message => (
	method => Object,
	positional => [BitcoinDigest],
);

sub sign_message
{
	my ($self, $digest_result) = @_;
	my $algorithm = $self->taproot_output ? 'schnorr' : 'default';

	Bitcoin::Crypto::Exception::Sign->raise(
		'cannot sign a message with a public key'
	) unless $self->_is_private;

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			return $algorithms{$algorithm}{signing_method}->($self, $digest_result->hash);
		}
	);
}

signature_for sign_transaction => (
	method => Object,
	positional => [
		InstanceOf ['Bitcoin::Crypto::Transaction'],
		HashRef, {slurpy => !!1}
	],
);

sub sign_transaction
{
	my ($self, $transaction, $args) = @_;

	$args->{transaction} = $transaction;
	$args->{key} = $self;
	my $signer = Bitcoin::Crypto::Transaction::Sign->new($args);
	$signer->sign;

	return;
}

signature_for verify_message => (
	method => Object,
	positional => [BitcoinDigest, ByteStr],
);

sub verify_message
{
	my ($self, $digest_result, $signature) = @_;
	my $algorithm = $self->taproot_output ? 'schnorr' : 'default';

	my $valid = !!0;
	try {
		$valid = $algorithms{$algorithm}{verification_method}->($self, $signature, $digest_result->hash);
	};

	return $valid;
}

1;

