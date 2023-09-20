package Bitcoin::Crypto::Transaction::Sign;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types qw(InstanceOf ByteStr PositiveInt PositiveOrZeroInt BitcoinScript Tuple Bool);

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

has field 'segwit' => (
	isa => Bool,
	writer => 1,
	lazy => sub {
		my $self = shift;
		return $self->input->utxo->output->locking_script->is_native_segwit;
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

sub _get_old_signature
{
	my ($self) = @_;

	if ($self->segwit) {
		return [@{$self->input->witness // []}];
	}
	else {
		my $old_script = $self->input->signature_script->operations;
		my @result;
		foreach my $part (@$old_script) {
			if ($part->[0]->name =~ /^OP_PUSHDATA/) {

				# using OP_PUSHDATA, as operations present most data pushes as this
				push @result, $part->[2];
			}
			elsif ($part->[0]->name =~ /^OP_\d+$/) {

				# first index is the whole op, so this gets the push from OP_0 - OP_15
				push @result, $part->[1];
			}
			else {
				die sprintf 'previous signature not a PUSH operation (%s)', $part->[0]->name;
			}
		}

		return \@result;
	}
}

sub _set_signature
{
	my ($self, $signature_parts, $append) = @_;

	if ($self->segwit) {
		if (!$append) {
			$self->input->set_witness([]);
		}

		push @{$self->input->witness}, @$signature_parts;
	}
	else {
		if (!$append) {
			my $script = btc_script->new;
			$self->input->set_signature_script($script);
		}

		foreach my $part (@$signature_parts) {
			$self->input->signature_script->push($part);
		}
	}
}

# NOTE: should only be run in P2SH after initial checks. P2SH script is run
# (without the transaction access) to verify whether HASH160 checksum matches.
# If it does, witness program is a is a nested segwit script.
sub _check_segwit_nested
{
	my ($self) = @_;

	my $check_locking_script = sub {
		my ($program) = @_;

		my $runner = $self->input->utxo->output->locking_script->run(
			[$program->to_serialized]
		);

		return $runner->success;
	};

	my @to_check = (
		$self->key->get_public_key->witness_program,    # P2SH(P2WPKH)
	);

	# P2SH(P2WSH)
	push @to_check, $self->redeem_script->witness_program
		if $self->has_redeem_script;

	foreach my $program (@to_check) {
		if ($check_locking_script->($program)) {
			return $program;
		}
	}

	return undef;
}

sub _sign_P2PK
{
	my ($self, $signature) = @_;

	$self->_set_signature(
		[
			$signature // $self->_get_signature()
		]
	);
}

sub _sign_P2PKH
{
	my ($self, $signature) = @_;

	$self->_set_signature(
		[
			$signature // $self->_get_signature(),
			$self->key->get_public_key->to_serialized
		]
	);
}

sub _sign_P2MS
{
	my ($self, $signature) = @_;

	die 'trying to sign payout from P2MS but no multisig was specified'
		unless $self->has_multisig;

	my ($this_signature, $total_signatures) = @{$self->multisig};

	my $sig = $self->_get_old_signature;
	$sig->[0] = "\x00";

	foreach my $sig_num (1 .. $total_signatures) {
		if ($sig_num == $this_signature) {

			# set this signature
			$sig->[$sig_num] = $signature // $self->_get_signature();
		}
		else {
			# Do not touch other signatures if they exist at all
			$sig->[$sig_num] //= "\x00";
		}
	}

	# cut off any remaining signature parts (like P2SH serialized script)
	$#$sig = $total_signatures;

	$self->_set_signature($sig);
}

sub _sign_P2SH
{
	my ($self) = @_;

	my $segwit_nested = $self->_check_segwit_nested;
	if (defined $segwit_nested) {
		$self->set_segwit(!!1);

		# for nested segwit, signature script need to be present before signing
		# for proper transaction digests to be generated
		$self->input->set_signature_script(
			btc_script->new->push($segwit_nested->to_serialized)
		);
		$self->_sign_type($segwit_nested->type, $self->_get_signature($segwit_nested->to_serialized));
	}
	else {
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
}

sub _sign_P2WPKH
{
	my ($self, $signature) = @_;

	$self->_set_signature(
		[
			$signature // $self->_get_signature(),
			$self->key->get_public_key->to_serialized
		]
	);
}

sub _sign_P2WSH
{
	my ($self) = @_;

	die 'trying to sign payout from P2WSH but no redeem_script was specified'
		unless $self->has_redeem_script;

	my $redeem_script = $self->redeem_script;
	die 'cannot automatically sign with a non-standard P2WSH redeem script'
		unless $redeem_script->has_type;
	die 'P2SH nested inside P2WSH'
		if $redeem_script->type eq 'P2SH';
	die 'P2WSH nested inside P2WSH'
		if $redeem_script->type eq 'P2WSH';

	$self->_sign_type($redeem_script->type, $self->_get_signature($redeem_script->to_serialized));
	$self->_set_signature([$redeem_script->to_serialized], !!1);
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

