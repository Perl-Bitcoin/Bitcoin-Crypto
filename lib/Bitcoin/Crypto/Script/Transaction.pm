package Bitcoin::Crypto::Script::Transaction;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Helpers qw(die_no_trace);
use Bitcoin::Crypto::Exception;

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
	clearer => -hidden,
);

has option 'script_tree' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Tree'],
	writer => 1,
	clearer => -hidden,
);

has option 'sigop_budget' => (
	isa => Int,
	writer => -hidden,
	clearer => -hidden,
);

sub _clear
{
	my $self = shift;

	# IMPORTANT: all data but input_index MUST be cleared here (clear or set
	# default)
	$self->set_taproot_ext_flag(0);
	$self->_clear_taproot_annex;
	$self->_clear_script_tree;
	$self->_clear_sigop_budget;
}

sub get_digest_object
{
	my ($self, %args) = @_;

	my $annex = $self->taproot_annex;

	return $self->transaction->get_digest_object(
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
	return shift->get_digest_object(@_)->get_digest;
}

sub this_input
{
	my $self = shift;

	return $self->inputs->[$self->input_index];
}

sub set_sigop_budget
{
	my ($self, $witness_size) = @_;

	$self->_set_sigop_budget(50 + $witness_size);
}

sub reduce_sigop_budget
{
	my $self = shift;

	my $budget = $self->sigop_budget;
	die_no_trace 'no sigop budget defined for the transaction object'
		unless defined $budget;

	$budget -= 50;
	$self->_set_sigop_budget($budget);
	return $budget >= 0;
}

sub is_segwit
{
	my $self = shift;

	return
		$self->flags->segwit
		&& $self->this_input->is_segwit;
}

sub is_native_segwit
{
	my $self = shift;

	return
		$self->flags->segwit
		&& $self->this_input->utxo->output->locking_script->is_native_segwit;
}

sub is_taproot
{
	my $self = shift;

	return
		$self->flags->taproot
		&& $self->this_input->is_taproot;
}

1;

