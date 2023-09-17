package Bitcoin::Crypto::Transaction::Sign;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types qw(InstanceOf ByteStr PositiveInt PositiveOrZeroInt BitcoinScript Tuple);

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
);

has param 'key' => (
	isa => InstanceOf ['Bitcoin::Crypto::Key::Private'],
);

has param 'signing_index' => (
	isa => PositiveOrZeroInt,
	default => 0,
);

has option 'redeem_script' => (
	coerce => BitcoinScript,
);

has option 'multisig' => (
	coerce => Tuple [PositiveInt, PositiveInt],
);

has param 'sighash' => (
	isa => PositiveInt,
	default => Bitcoin::Crypto::Constants::sighash_all,
);

has field 'input' => (
	lazy => sub {
		my $self = shift;
		return $self->transaction->inputs->[$self->signing_index];
	},
);

sub _get_signature
{
	my ($self, $subscript) = @_;

	my $digest = $self->transaction->get_digest(
		signing_index => $self->signing_index,
		sighash => $self->sighash,
		($subscript ? (signing_subscript => $subscript) : ()),
	);

	my $signature = $self->key->sign_message($digest);
	$signature .= pack 'C', $self->sighash;

	return $signature;
}

sub _sign_P2PK
{
	my ($self, $signature) = @_;

	$self->input->set_signature_script(
		btc_script->new->push($signature // $self->_get_signature())
	);
}

sub _sign_P2PKH
{
	my ($self, $signature) = @_;

	$self->input->set_signature_script(
		btc_script->new
			->push($signature // $self->_get_signature())
			->push($self->key->get_public_key->to_serialized)
	);
}

sub _sign_P2MS
{
	my ($self, $signature) = @_;

	die 'trying to sign payout from P2MS but no multisig was specified'
		unless $self->has_multisig;

	my ($this_signature, $total_signatures) = @{$self->multisig};

	my $old_script = $self->input->signature_script->operations;
	my $script = btc_script->new->add('OP_0');

	foreach my $sig_num (1 .. $total_signatures) {
		if ($sig_num == $this_signature) {
			$script->push($signature // $self->_get_signature());
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

	$self->input->set_signature_script($script);
}

sub _sign_P2SH
{
	my ($self) = @_;

	die 'trying to sign payout from P2SH but no redeem_script was specified'
		unless $self->has_redeem_script;

	my $redeem_script = $self->redeem_script;
	die 'cannot automatically sign with a non-standard P2SH redeem script'
		unless $redeem_script->has_type;
	die 'P2SH nested inside P2SH'
		if $redeem_script->type eq 'P2SH';

	$self->_sign_type($redeem_script->type, $self->_get_signature($redeem_script->to_serialized));
	$self->input->signature_script->push($redeem_script->to_serialized);
}

sub _sign_P2WPKH
{
	my ($self, $signature) = @_;

	$self->input->set_witness(
		[
			$signature // $self->_get_signature(),
			$self->key->get_public_key->to_serialized
		]
	);
}

sub _sign_P2WSH
{
}

sub _sign_type
{
	my ($self, $type, @rest) = @_;

	my $method = "_sign_$type";
	Bitcoin::Crypto::Exception::ScriptType->raise(
		"don't know how to sign standard script type $type"
	) unless $self->can($method);

	return $self->$method(@rest);
}

sub sign
{
	my ($self) = @_;

	Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			die 'no such input' if !$self->input;

			my $utxo = $self->input->utxo->output;

			die 'cannot automatically sign a non-standard locking script'
				if !$utxo->is_standard;

			$self->_sign_type($utxo->locking_script->type);
		},
		"Can't sign transaction input " . $self->signing_index
	);
}

1;

