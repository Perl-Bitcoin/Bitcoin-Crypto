package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Helpers qw(carp_once ecc);
use Bitcoin::Crypto::Util qw(hash256);
use Bitcoin::Crypto::Transaction::Sign;
use Moo::Role;

requires qw(
	raw_key
	_is_private
);

signature_for sign_message => (
	method => Object,
	positional => [ByteStr],
);

sub sign_message
{
	my ($self, $preimage) = @_;

	Bitcoin::Crypto::Exception::Sign->raise(
		'cannot sign a message with a public key'
	) unless $self->_is_private;

	my $digest = hash256($preimage);

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			return ecc->sign_digest($self->raw_key, $digest);
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
	my $digest = hash256($preimage);

	return Bitcoin::Crypto::Exception::Verify->trap_into(
		sub {
			my $normalized = ecc->normalize_signature($signature);
			return !!0 if $normalized ne $signature;
			return ecc->verify_digest($self->raw_key('public'), $signature, $digest);
		}
	);
}

1;

