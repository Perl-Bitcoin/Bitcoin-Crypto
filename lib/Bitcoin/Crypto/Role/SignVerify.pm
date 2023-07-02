package Bitcoin::Crypto::Role::SignVerify;

use v5.10;
use strict;
use warnings;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Types qw(Object Str Tuple ByteStr InstanceOf PositiveInt PositiveOrZeroInt BitcoinScript);
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
		redeem_script => BitcoinScript,
		{optional => 1},
		multisig => Tuple [PositiveInt, PositiveInt],
		{optional => 1},
		sighash => PositiveInt,
		{default => Bitcoin::Crypto::Constants::sighash_all}
	],
);

sub sign_transaction
{
	my ($self, $transaction, $args) = @_;
	my $input_index = $args->signing_index;
	my $input = $transaction->inputs->[$input_index];
	my $sighash = $args->sighash;

	my $sign_sref = sub {
		my ($subscript) = @_;

		my $digest = $transaction->get_digest(
			signing_index => $input_index,
			sighash => $sighash,
			($subscript ? (signing_subscript => $subscript) : ()),
		);

		my $signature = $self->sign_message($digest, 'hash256');
		$signature .= pack 'C', $sighash;

		return $signature;
	};

	my $types;
	my $run_type = sub {
		my $type = shift;

		Bitcoin::Crypto::Exception::ScriptType->raise(
			"don't know how to sign standard script type $type"
		) if !$types->{$type};

		$types->{$type}->(@_);
	};

	$types = {
		P2PK => sub {
			my ($signature) = @_;

			$input->set_signature_script(
				btc_script->new->push($signature // $sign_sref->())
			);
		},
		P2PKH => sub {
			my ($signature) = @_;

			$input->set_signature_script(
				btc_script->new
					->push($signature // $sign_sref->())
					->push($self->get_public_key->to_str)
			);
		},
		P2MS => sub {
			my ($signature) = @_;
			my $ms_info = $args->multisig;

			die 'trying to sign payout from P2MS but no multisig was specified'
				unless $ms_info;

			my ($this_signature, $total_signatures) = @$ms_info;

			my $old_script = $input->signature_script->operations;
			my $script = btc_script->new->add('OP_0');

			foreach my $sig_num (1 .. $total_signatures) {
				if ($sig_num == $this_signature) {
					$script->push($signature // $sign_sref->());
				}
				else {
					my $prev = $old_script->[$sig_num];

					# NOTE: using OP_PUSHDATA1, as operations present data pushes as this
					if (defined $prev) {
						die sprintf 'previous signature not a PUSH operation (%s)', $prev->[0]->name
							unless $prev->[0]->name eq 'OP_PUSHDATA1';
						$prev = $prev->[2];
					}

					$script->push($prev // "\x00");
				}
			}

			$input->set_signature_script($script);
		},
		P2SH => sub {
			my $redeem_script = $args->redeem_script;

			die 'trying to sign payout from P2SH but no redeem_script was specified'
				unless $redeem_script;
			die 'cannot automatically sign with a non-standard P2SH redeem script'
				unless $redeem_script->has_type;
			die 'P2SH nested inside P2SH'
				if $redeem_script->type eq 'P2SH';

			$run_type->($redeem_script->type, $sign_sref->($redeem_script->to_serialized));
			$input->signature_script->push($redeem_script->to_serialized);
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
			die 'no such input' if !$input;

			my $utxo = $input->utxo->output;

			die 'cannot automatically sign a non-standard locking script'
				if !$utxo->is_standard;

			$run_type->($utxo->locking_script->type);
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

