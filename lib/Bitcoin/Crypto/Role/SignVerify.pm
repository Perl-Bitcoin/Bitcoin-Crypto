package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Helpers qw(carp_once ecc);
use Bitcoin::Crypto::Util qw(hash256 tagged_hash);
use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::Crypto::Transaction::Sign;
use Bitcoin::Crypto::Constants;
use Moo::Role;

requires qw(
	raw_key
	_is_private
);

signature_for sign_message => (
	method => Object,
	head => [ByteStr],
	named => [
		algorithm => SignatureAlgorithm,
		{default => Bitcoin::Crypto::Constants::signing_algorithm_ecdsa},
		taproot_tweak_suffix => Maybe [ByteStr],
		{default => undef},
	],
	bless => !!0,
);

sub sign_message
{
	my ($self, $preimage, $args) = @_;

	Bitcoin::Crypto::Exception::Sign->raise(
		'cannot sign a message with a public key'
	) unless $self->_is_private;

	my %algorithms = (
		(Bitcoin::Crypto::Constants::signing_algorithm_ecdsa) => {
			digest => \&hash256,
			signing_method => sub { ecc->sign_digest(@_) },
			raw_key => sub { $self->raw_key },
		},
		(Bitcoin::Crypto::Constants::signing_algorithm_schnorr) => {
			digest => sub { tagged_hash(shift, 'TapSighash') },
			signing_method => sub { ecc->sign_digest_schnorr(@_) },
			raw_key => sub {
				$self->taproot_tweaked_key(
					tweak_suffix => $args->{taproot_tweak_suffix}
				);
			},
		},
	);

	my $key = $algorithms{$args->{algorithm}}{raw_key}->();
	my $digest = $algorithms{$args->{algorithm}}{digest}->($preimage);

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			return $algorithms{$args->{algorithm}}{signing_method}->($key, $digest);
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

