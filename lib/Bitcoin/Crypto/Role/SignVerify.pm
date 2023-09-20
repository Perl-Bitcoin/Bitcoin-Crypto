package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Object Str ByteStr InstanceOf HashRef);
use Bitcoin::Crypto::Helpers qw(carp_once);    # load Math::BigInt
use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::Crypto::Transaction::Sign;
use Moo::Role;

use constant HAS_DETERMINISTIC_SIGNATURES => eval { require Crypt::Perl } && Crypt::Perl->VERSION gt '0.33';

requires qw(
	key_instance
	_is_private
);

has field '_crypt_perl_prv' => (
	isa => InstanceOf ['Crypt::Perl::ECDSA::PrivateKey'],
	lazy => sub {
		require Crypt::Perl::ECDSA::Parse;
		return Crypt::Perl::ECDSA::Parse::private($_[0]->key_instance->export_key_der('private'));
	}
);

sub _fix_der_signature
{
	my ($self, $signature) = @_;

	return undef unless defined $signature;

	# https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format
	my $pos = 0;

	my $compound = substr $signature, $pos, 1;
	$pos += 1;

	my $total_len = unpack 'C', substr $signature, $pos, 1;
	$pos += 1;

	my $int1 = substr $signature, $pos, 1;
	$pos += 1;

	my $r_len = unpack 'C', substr $signature, $pos, 1;
	$pos += 1;

	my $r = substr $signature, $pos, $r_len;
	$pos += $r_len;

	my $int2 = substr $signature, $pos, 1;
	$pos += 1;

	my $s_len = unpack 'C', substr $signature, $pos, 1;
	$pos += 1;

	my $s = Math::BigInt->from_bytes(substr $signature, $pos, $s_len);
	$pos += $s_len;

	die 'invalid signature'
		unless $pos == length $signature;

	# fixup $s - must be below order / 2 (BIP62)
	my $order = $self->curve_order;
	if ($s > $order->copy->btdiv(2)) {
		$s = $order - $s;
	}

	$s = $s->as_bytes;
	$total_len = $total_len - $s_len + length $s;
	$s_len = length $s;

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

signature_for sign_message => (
	method => Object,
	positional => [ByteStr, Str, {default => 'hash256'}],
);

sub sign_message
{
	my ($self, $message, $algorithm) = @_;

	Bitcoin::Crypto::Exception::Sign->raise(
		'cannot sign a message with a public key'
	) unless $self->_is_private;

	if ($algorithm eq 'hash256') {
		$algorithm = 'sha256';
		$message = sha256($message);
	}

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			my $signature;
			if (HAS_DETERMINISTIC_SIGNATURES) {
				my $sub = "sign_${algorithm}";
				$signature = $self->_crypt_perl_prv->$sub($message);
			}
			else {
				carp_once
					'Current implementation of CryptX signature generation does not produce deterministic results. For better security, install the Crypt::Perl module.';
				$signature = $self->key_instance->sign_message($message, $algorithm);
			}

			return $self->_fix_der_signature($signature);
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
	positional => [ByteStr, ByteStr, Str, {default => 'hash256'}],
);

sub verify_message
{
	my ($self, $message, $signature, $algorithm) = @_;

	if ($algorithm eq 'hash256') {
		$algorithm = 'sha256';
		$message = sha256($message);
	}

	return Bitcoin::Crypto::Exception::Verify->trap_into(
		sub {
			$self->key_instance->verify_message($signature, $message, $algorithm);
		}
	);
}

1;

