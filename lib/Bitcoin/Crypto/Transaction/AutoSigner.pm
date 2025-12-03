package Bitcoin::Crypto::Transaction::AutoSigner;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Helpers qw(die_no_trace);
use Bitcoin::Crypto::Types -types;

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
);

has param 'key' => (
	isa => InstanceOf ['Bitcoin::Crypto::Key::Private'],
);

has param 'signing_index' => (
	isa => PositiveOrZeroInt,
);

has option 'redeem_script' => (
	coerce => BitcoinScript,
);

has option 'multisig' => (
	coerce => Tuple [PositiveInt, PositiveInt],
);

has option 'sighash' => (
	isa => PositiveOrZeroInt,
	writer => -hidden,
);

has option 'script_tree' => (
	coerce => BitcoinScriptTree,
);

has field '_compat' => (
	writer => 1,
	default => !!0,
);

has field 'input' => (
	lazy => sub {
		my $self = shift;
		return $self->transaction->inputs->[$self->signing_index];
	},
);

sub _get_old_signature
{
	my ($self) = @_;

	if ($self->input->is_segwit) {
		return [@{$self->input->witness // []}];
	}
	else {
		my $old_script = $self->input->signature_script->operations;
		my @result;
		foreach my $part (@$old_script) {
			push @result, $part->[2]
				if $part->[0]->pushop;
		}

		return \@result;
	}
}

sub _sign_P2PK
{
	my ($self, $signature) = @_;

	$self->transaction
		->sign(
			signing_index => $self->signing_index,
			compat => $self->_compat,
		)
		->add_signature($self->key, sighash => $self->sighash)
		->finalize;
}

sub _sign_P2PKH
{
	my ($self) = @_;

	return $self->_sign_P2PK;
}

sub _sign_P2MS
{
	my ($self, $signature) = @_;

	die_no_trace 'trying to sign payout from P2MS but no multisig was specified'
		unless $self->has_multisig;

	my ($this_signature, $total_signatures) = @{$self->multisig};

	my $signer = $self->transaction
		->sign(
			signing_index => $self->signing_index,
			compat => $self->_compat,
			($self->redeem_script ? (script => $self->redeem_script) : ()),
		);

	my $sig = $self->_get_old_signature;

	# process signatures in reverse order, since add_signature works that way
	foreach my $sig_num (reverse 1 .. $total_signatures) {
		if ($sig_num == $this_signature) {

			# set this signature
			$signer->add_signature($self->key, sighash => $self->sighash);
		}
		else {

			# Do not touch other signatures if they exist at all
			$signer->add_signature($sig->[$sig_num] // '');
		}
	}

	$signer
		->finalize_multisignature
		->finalize;
}

sub _sign_P2WPKH
{
	my ($self) = @_;

	return $self->_sign_P2PK;
}

sub _sign_P2TR
{
	my ($self) = @_;
	my $script_tree = $self->script_tree;

	# signs key path only
	$self->transaction
		->sign(
			signing_index => $self->signing_index,
			($script_tree ? (script_tree => $script_tree) : ()),
		)
		->add_signature($self->key, sighash => $self->sighash)
		->finalize;
}

sub _sign_script
{
	my ($self, $script, $nested) = @_;
	my $type = $script->type;

	my $method = $self->can("_sign_$type");
	return $self->$method if $method;

	Bitcoin::Crypto::Exception::ScriptType->raise(
		"don't know how to sign nested standard script type $type"
	) if $nested;

	if ($type eq 'P2SH') {
		if (!$self->has_redeem_script) {

			# P2SH but no redeem script - must be compat P2WPKH
			$self->_set_compat(!!1);
			return $self->_sign_P2WPKH;
		}
		elsif (!$self->_compat) {

			# this may be compat P2WSH - let further code handle it
			my $witness_el = $self->redeem_script->witness_program->to_serialized;
			$self->_set_compat(!!1) if $script->run([$witness_el])->success;
		}
	}

	my $redeem_type = $self->has_redeem_script && $self->redeem_script->type;
	return $self->_sign_script($self->redeem_script, -nested)
		if $redeem_type && ($type eq 'P2SH' || $type eq 'P2WSH');

	Bitcoin::Crypto::Exception::ScriptType->raise(
		"don't know how to sign standard script type $type"
	);
}

sub sign
{
	my ($self) = @_;

	Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			die_no_trace 'no such input' if !$self->input;

			my $utxo = $self->input->utxo->output;

			die_no_trace 'cannot automatically sign a non-standard locking script'
				if !$utxo->is_standard;

			$self->_sign_script($utxo->locking_script);
		},
		"Can't sign transaction input " . $self->signing_index
	);
}

1;

