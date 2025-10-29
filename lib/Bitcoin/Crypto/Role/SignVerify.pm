package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use Try::Tiny;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Helpers qw(carp_once ecc);
use Bitcoin::Crypto::Util qw(hash256 tagged_hash);
use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::Crypto::Transaction::Sign;
use Bitcoin::Crypto::Constants;
use Moo::Role;

requires qw(
	raw_key
	taproot
	_is_private
);

my %algorithms = (
	default => {
		digest => \&hash256,
		signing_method => sub {
			my ($key, $digest) = @_;

			return ecc->sign_digest($key->raw_key, $digest);
		},
		verification_method => sub {
			my ($key, $signature, $digest) = @_;

			my $normalized = ecc->normalize_signature($signature);
			return !!0 if $normalized ne $signature;
			return ecc->verify_digest($key->raw_key('public'), $signature, $digest);
		},
	},
	schnorr => {
		digest => sub { tagged_hash('TapSighash', shift) },
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
	positional => [ByteStr],
);

sub sign_message
{
	my ($self, $preimage) = @_;
	my $algorithm = $self->taproot ? 'schnorr' : 'default';

	Bitcoin::Crypto::Exception::Sign->raise(
		'cannot sign a message with a public key'
	) unless $self->_is_private;

	my $digest = $algorithms{$algorithm}{digest}->($preimage);

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			return $algorithms{$algorithm}{signing_method}->($self, $digest);
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
	positional => [ByteStr, ByteStr],
);

sub verify_message
{
	my ($self, $preimage, $signature) = @_;
	my $algorithm = $self->taproot ? 'schnorr' : 'default';

	my $digest = $algorithms{$algorithm}{digest}->($preimage);

	my $valid = !!0;
	try {
		$valid = $algorithms{$algorithm}{verification_method}->($self, $signature, $digest);
	};

	return $valid;
}

1;

