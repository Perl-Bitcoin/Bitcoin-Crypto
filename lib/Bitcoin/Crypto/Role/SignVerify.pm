package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Types qw(Object Str ByteStr InstanceOf PositiveInt PositiveOrZeroInt);
use Bitcoin::Crypto::Helpers qw(carp_once);
use Bitcoin::Crypto::Constants;
use Crypt::Digest::SHA256 qw(sha256);
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

signature_for sign_message => (
	method => Object,
	positional => [ByteStr, Str, {default => 'sha256'}],
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
			if (HAS_DETERMINISTIC_SIGNATURES) {
				my $sub = "sign_${algorithm}";
				return $self->_crypt_perl_prv->$sub($message);
			}
			else {
				carp_once
					'Current implementation of CryptX signature generation does not produce deterministic results. For better security, install the Crypt::Perl module.';
				return $self->key_instance->sign_message($message, $algorithm);
			}
		}
	);
}

signature_for sign_transaction => (
	method => Object,
	head => [InstanceOf ['Bitcoin::Crypto::Transaction']],
	named => [
		signing_index => PositiveOrZeroInt,
		{default => 0},
		sighash => PositiveInt,
		{default => Bitcoin::Crypto::Constants::sighash->{ALL}}
	],
);

sub sign_transaction
{
	my ($self, $transaction, $args) = @_;
	my $input_index = $args->signing_index;
	my $sighash = $args->sighash;

	state $types = {
		P2PK => sub {
			my ($self, $input, $signature) = @_;

			$input->set_signature_script(
				btc_script->new->push($signature)
			);
		},
		P2PKH => sub {
			my ($self, $input, $signature) = @_;

			$input->set_signature_script(
				btc_script->new
					->push($signature)
					->push($self->get_public_key->to_str)
			);
		},
		P2SH => sub {

			# TODO
		},
		P2WPKH => sub {

			# TODO
		},
		P2WSH => sub {

			# TODO
		},
	};

	Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			my $input = $transaction->inputs->[$input_index];
			die 'no such input' if !$input;

			my $utxo = $input->utxo->output;

			die 'cannot automatically sign a non-standard locking script'
				if !$utxo->is_standard;

			my $digest = $transaction->get_digest(
				signing_index => $input_index,
				sighash => $sighash
			);

			my $signature = $self->sign_message($digest, 'hash256');
			$signature .= pack 'C', $sighash;

			my $type = $utxo->locking_script->type;

			Bitcoin::Crypto::Exception::ScriptType->raise(
				"unknown standard script type $type"
			) if !$types->{$type};

			$types->{$type}->($self, $input, $signature);
		},
		"Can't sign transaction input $input_index"
	);

	return;
}

signature_for verify_message => (
	method => Object,
	positional => [ByteStr, ByteStr, Str, {default => 'sha256'}],
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

