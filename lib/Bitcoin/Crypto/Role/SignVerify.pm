package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use Try::Tiny;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Helpers qw(ecc);
use Bitcoin::Crypto::Transaction::AutoSigner;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Transaction::Flags;
use Moo::Role;

requires qw(
	raw_key
	taproot_output
	_is_private
);

# this does not fix low s, just strict encoding
sub _strict_ecdsa_signature
{
	my ($signature) = @_;

	# https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format
	# also:
	# - ignore any trailing data
	# - fix negative r and s

	my $pos = 0;
	my $compound = substr $signature, $pos++, 1;
	my $total_len = unpack 'C', substr $signature, $pos++, 1;
	my $int1 = substr $signature, $pos++, 1;
	my $r_len = unpack 'C', substr $signature, $pos++, 1;
	my $r = substr $signature, $pos, $r_len;
	$pos += $r_len;
	my $int2 = substr $signature, $pos++, 1;
	my $s_len = unpack 'C', substr $signature, $pos++, 1;
	my $s = substr $signature, $pos, $s_len;
	$pos += $s_len;

	# top bit may be 1, so prepend with zero to avoid being interpreted as
	# negative
	$r = "\x00$r" and ++$total_len and ++$r_len
		if unpack('C', $r) & 0x80;
	$s = "\x00$s" and ++$total_len and ++$s_len
		if unpack('C', $s) & 0x80;

	# return extracted strict signature
	return join '',
		$compound,
		pack('C', $total_len),
		$int1,
		pack('C', $r_len),
		$r,
		$int2,
		pack('C', $s_len),
		$s,
		;
}

my %algorithms = (
	default => {
		signing_method => sub {
			my ($key, $digest) = @_;

			return ecc->sign_digest($key->raw_key, $digest);
		},
		verification_method => sub {
			my ($key, $signature, $digest, $flags) = @_;

			# strict DER / strict encoding / other strict signature features
			# are currently aggregated in strict_signatures
			if (!$flags->strict_signatures) {
				$signature = _strict_ecdsa_signature($signature);
			}
			else {
				my $normalized = ecc->normalize_signature($signature);
				return !!0 if $normalized ne $signature;
			}

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
	my $signer = Bitcoin::Crypto::Transaction::AutoSigner->new($args);
	$signer->sign;

	return;
}

signature_for verify_message => (
	method => Object,
	head => [BitcoinDigest, ByteStr],
	named => [
		flags => Maybe [InstanceOf ['Bitcoin::Crypto::Transaction::Flags']],
		{default => undef},
	],
	bless => !!0,
);

sub verify_message
{
	my ($self, $digest_result, $signature, $args) = @_;
	my $algorithm = $self->taproot_output ? 'schnorr' : 'default';
	my $flags = $args->{flags} // Bitcoin::Crypto::Transaction::Flags->new;

	my $valid = !!0;
	try {
		$valid = $algorithms{$algorithm}{verification_method}->(
			$self,
			$signature,
			$digest_result->hash,
			$flags,
		);
	};

	return $valid;
}

1;

