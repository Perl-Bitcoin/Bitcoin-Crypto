package Bitcoin::Crypto::Transaction::Signer::P2TR;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Util qw(get_taproot_ext);

use namespace::clean;

extends 'Bitcoin::Crypto::Transaction::Signer::Segwit';

has option 'script_tree' => (
	coerce => BitcoinScriptTree,
);

has option 'leaf_id' => (
	isa => Int,
);

has option 'public_key' => (
	isa => InstanceOf ['Bitcoin::Crypto::Key::Public'],
);

has param 'taproot_ext_flag' => (
	isa => PositiveOrZeroInt,
	default => 1,
);

has field 'script_spend' => (
	lazy => 1,
);

has extended 'script' => (
	lazy => 1,
	init_arg => undef,
);

sub _multisigop
{
	return !!0;
}

sub _build_script
{
	my ($self) = @_;

	if ($self->script_spend) {
		return $self->script_tree->get_tapleaf_script($self->leaf_id);
	}
	else {
		my $segwit_program = $self->transaction->inputs->[$self->signing_index]->utxo->output->locking_script;
		my $runner = $segwit_program->run;
		my $pubkey = $runner->stack->[-1];

		return Bitcoin::Crypto::Script::Common->new(TR => $pubkey);
	}
}

sub _build_script_spend
{
	my ($self) = @_;

	return $self->has_leaf_id && $self->has_script_tree && $self->has_public_key;
}

sub _build_runner
{
	my ($self) = @_;

	my $runner = $self->SUPER::_build_runner;

	if ($self->script_spend) {
		$runner->transaction->set_taproot_ext_flag(1);
		$runner->transaction->set_script_tree($self->script_tree);
	}

	return $runner;
}

sub _get_taproot_ext
{
	my ($self, $codesep_pos) = @_;

	return undef unless $self->script_spend;

	my $flag = $self->taproot_ext_flag;
	my $ext = get_taproot_ext(
		$flag,
		script_tree => $self->script_tree,
		leaf_id => $self->leaf_id,
		codesep_pos => $codesep_pos,
	);

	return $ext;
}

sub _find_next_sigop
{
	my ($self) = @_;

	my $runner = $self->SUPER::_find_next_sigop;

	# set some budget to avoid failure
	$runner->transaction->set_sigop_budget(0);
	return $runner;
}

sub _initialize
{
	my ($self) = @_;

	if ($self->script_spend) {
		my $control_block = $self->script_tree->get_control_block($self->leaf_id, $self->public_key);
		push @{$self->_signature}, $control_block->to_serialized, $self->script->to_serialized;
	}

	$self->SUPER::_initialize;
}

sub _get_signature
{
	my ($self, $privkey, $args) = @_;
	my $runner = $self->_runner;

	# make sure we have a taproot output key
	$privkey = $privkey->get_taproot_output_key(
		$self->has_script_tree ? $self->script_tree->get_merkle_root : undef
	);
	my $pubkey = $privkey->get_public_key;

	# taproot opcodes simplify things - no need to handle multisig
	my $script_pubkey = $runner->stack->[-1];
	Bitcoin::Crypto::Exception::Sign->raise(
		'bad private key for public key encountered in script sigop at position ' . $runner->pos
	) unless $script_pubkey eq $pubkey->get_xonly_key;

	my $digest_obj = $runner->transaction->get_digest_object(
		sighash => $args->{sighash},
		taproot_ext => $self->_get_taproot_ext($runner->codeseparator),
	);

	my $signature = $privkey->sign_message($digest_obj->get_digest);
	if ($digest_obj->sighash != Bitcoin::Crypto::Constants::sighash_default) {
		$signature .= pack 'C', $digest_obj->sighash;
	}

	return $signature;
}

sub finalize_multisignature
{
	Bitcoin::Crypto::Exception::Sign->raise(
		'taproot transactions do not support multisignatures'
	);
}

1;

