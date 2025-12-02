package Bitcoin::Crypto::Transaction::Signer::CompatSegwit;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

extends 'Bitcoin::Crypto::Transaction::Signer::Segwit';

has field 'witness_program' => (
	isa => BitcoinScript,
	trigger => 1,
	writer => 1,
);

sub _build_runner
{
	my ($self) = @_;

	my $ind = $self->signing_index;
	my $temp_tx = $self->transaction->clone;
	$temp_tx->inputs->[$ind] = $temp_tx->inputs->[$ind]->clone;

	# build a runner with temporary transaction. No need to call SUPER version,
	# since it would be doing the same work twice
	my $runner = Bitcoin::Crypto::Script::Runner->new(
		transaction => $temp_tx
	);

	$runner->transaction->set_input_index($ind);
	$runner->start($self->script);

	return $runner;
}

sub _trigger_witness_program
{
	my ($self) = @_;

	$self->_runner->transaction->inputs->[$self->signing_index]->set_signature_script(
		btc_script->new->push_bytes($self->witness_program->to_serialized)
	);
}

sub _finalize
{
	my ($self) = @_;

	my $witness_program = $self->witness_program;

	Bitcoin::Crypto::Exception::Sign->raise(
		'signature is missing a witness program'
	) unless $witness_program;

	$self->transaction->inputs->[$self->signing_index]->set_signature_script(
		btc_script->new->push_bytes($witness_program->to_serialized)
	);

	$self->SUPER::_finalize;
}

1;

