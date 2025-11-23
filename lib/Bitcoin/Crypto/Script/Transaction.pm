package Bitcoin::Crypto::Script::Transaction;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

use namespace::clean;

# must be set via a trigger
has field 'runner' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Runner'],
	writer => 1,
	weak_ref => 1,
	handles => [
		qw(
			flags
		),
	],
);

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
	handles => [
		qw(
			version
			locktime
			inputs
			outputs
		)
	],
);

has param 'input_index' => (
	isa => PositiveOrZeroInt,
	writer => 1,
	default => 0,
);

has param 'taproot_ext_flag' => (
	isa => PositiveOrZeroInt,
	writer => 1,
	default => 0,
);

has param 'taproot_annex' => (
	coerce => ByteStr,
	writer => 1,
	required => 0,
);

has option 'script_tree' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Tree'],
	writer => 1,
);

has option 'sigop_budget' => (
	isa => Int,
	writer => -hidden,
);

sub get_digest_object
{
	my ($self, %args) = @_;

	my $annex = $self->taproot_annex;

	return $self->transaction->get_digest_object(
		flags => $self->flags,
		signing_index => $self->input_index,
		signing_subscript => $self->runner->subscript($args{signatures}),
		taproot_ext_flag => $self->taproot_ext_flag,
		(defined $annex ? (taproot_annex => $annex) : ()),
		(defined $args{sighash} ? (sighash => $args{sighash}) : ()),
		(defined $args{taproot_ext} ? (taproot_ext => $args{taproot_ext}) : ()),
	);
}

sub get_digest
{
	my $self = shift;

	return $self->get_digest_object(@_)->get_digest;
}

sub this_input
{
	my ($self) = @_;

	return $self->inputs->[$self->input_index];
}

sub set_sigop_budget
{
	my ($self, $witness_size) = @_;

	$self->_set_sigop_budget(50 + $witness_size);
}

sub reduce_sigop_budget
{
	my ($self) = @_;

	die 'no sigop budget defined for the transaction object'
		unless $self->has_sigop_budget;

	my $budget = $self->sigop_budget;
	$budget -= 50;
	$self->_set_sigop_budget($budget);
	return $budget >= 0;
}

sub is_native_segwit
{
	my ($self) = @_;

	return
		$self->flags->segwit
		&& $self->this_input->utxo->output->locking_script->is_native_segwit;
}

sub is_taproot
{
	my ($self) = @_;

	return
		$self->flags->taproot
		&& $self->this_input->utxo->output->locking_script->is_taproot;
}

1;

