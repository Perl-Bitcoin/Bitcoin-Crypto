package Bitcoin::Crypto::Role::PSBT::Signer;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;
use Types::Common -sigs;
use List::Util qw(any);

use Bitcoin::Crypto qw(btc_script_tree);
use Bitcoin::Crypto::Constants qw(:sighash);
use Bitcoin::Crypto::Transaction::Flags;

sub _input_has_witness_utxo
{
	my ($self, $input_index) = @_;

	my $witness_utxo = $self->get_all_fields('PSBT_IN_WITNESS_UTXO', $input_index);
	return !!$witness_utxo;
}

sub _update_modifiable_flags
{
	my ($self, $sighash) = @_;

	return unless $self->version == 2;

	# NOTE: SIGHASH_DEFAULT may not be correct for pre-taproot, but it's only
	# used to set modifiable flags, which will be the same for SIGHASH_ALL
	$sighash = $sighash ? $sighash->value : SIGHASH_ALL;

	my $modifiable = $self->get_all_fields('PSBT_GLOBAL_TX_MODIFIABLE');
	$modifiable //= $self
		->add_field(
			type => 'PSBT_GLOBAL_TX_MODIFIABLE',
			value => {
				inputs_modifiable => !!1,
				outputs_modifiable => !!1,
			},
		)
		->get_field('PSBT_GLOBAL_TX_MODIFIABLE');

	my $value = $modifiable->value;

	if (!($sighash & SIGHASH_ANYONECANPAY)) {
		$value->{inputs_modifiable} = !!0;
	}

	my $sighash_type = $sighash & 31;

	if ($sighash_type != SIGHASH_NONE) {
		$value->{outputs_modifiable} = !!0;
	}

	if ($sighash_type == SIGHASH_SINGLE) {
		$value->{has_sighash_single} = !!1;
	}

	# update the value back in the PSBT
	$modifiable->set_value($value);
}

sub _add_partial_signature_legacy
{
	my ($self, $input_index, $key, $signature, $sighash) = @_;

	$self->add_field(
		type => 'PSBT_IN_PARTIAL_SIG',
		index => $input_index,
		key => $key->get_public_key,
		value => $signature,
	);

	$self->_update_modifiable_flags($sighash);
}

sub _add_partial_signature_taproot
{
	my ($self, $input_index, $key, $signature, $sighash) = @_;

	# TODO: add support for PSBT_IN_TAP_SCRIPT_SIG
	$self->add_field(
		type => 'PSBT_IN_TAP_KEY_SIG',
		index => $input_index,
		value => $signature,
	);

	$self->_update_modifiable_flags($sighash);
}

sub _do_sign_P2PKH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	return 0 if $self->_input_has_witness_utxo($input_index);

	return 0 unless $key->get_public_key->get_hash eq $input->utxo->output->locking_script->get_raw_address;
	my $signer = $tx->sign(signing_index => $input_index, flags => Bitcoin::Crypto::Transaction::Flags->new_full);
	my $sighash = $self->get_all_fields('PSBT_IN_SIGHASH_TYPE', $input_index);

	# use transaction signer's ability to give us the signature
	my $signature = $signer->add_signature($key, sighash => $sighash ? $sighash->value : undef)
		->signature->[-1];

	$self->_add_partial_signature_legacy($input_index, $key, $signature, $sighash);
	return 1;
}

sub _do_sign_P2SH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	# is there a matching redeem script?
	my $redeem = $self->get_all_fields('PSBT_IN_REDEEM_SCRIPT', $input_index);
	return 0 unless $redeem;

	my $script = $redeem->value;
	return 0 unless $script->get_hash eq $input->utxo->output->locking_script->get_raw_address;

	my $type = $script->type;
	if ($type eq 'P2WPKH' || $type eq 'P2WSH') {
		my $method = "_do_sign_$type";
		return $self->$method($key, $tx, $input, $input_index, $script);
	}
	elsif ($type eq 'P2MS') {
		return 0 if $self->_input_has_witness_utxo($input_index);

		# TODO P2MS signing
	}

	return 0;
}

sub _do_sign_P2WPKH
{
	my ($self, $key, $tx, $input, $input_index, $compat_script) = @_;

	my $to_compare = $compat_script
		? $compat_script->get_raw_address
		: $input->utxo->output->locking_script->get_raw_address
		;

	return 0 unless $key->get_public_key->get_hash eq $to_compare;

	my $signer = $tx->sign(
		signing_index => $input_index,
		flags => Bitcoin::Crypto::Transaction::Flags->new_full,
		($compat_script ? (compat => !!1) : ()),
	);
	my $sighash = $self->get_all_fields('PSBT_IN_SIGHASH_TYPE', $input_index);

	# use transaction signer's ability to give us the signature
	my $signature = $signer->add_signature($key, sighash => $sighash ? $sighash->value : undef)
		->signature->[-1];

	$self->_add_partial_signature_legacy($input_index, $key, $signature, $sighash);
	return 1;
}

sub _do_sign_P2WSH
{
	my ($self, $key, $tx, $input, $input_index, $compat_script) = @_;

	# TODO: If a witnessScript is provided, the scriptPubKey or the redeemScript must be for that witnessScript

	# TODO
	return 0;
}

sub _do_sign_P2TR_keypath
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	my $tree_root = $self->get_all_fields('PSBT_IN_TAP_MERKLE_ROOT', $input_index);
	my $tree = $tree_root ? btc_script_tree->new(tree => [{hash => $tree_root->value}]) : undef;

	my $output_key = $key->get_public_key->get_taproot_output_key($tree ? $tree->get_merkle_root : ());
	return 0 unless $output_key->get_xonly_key eq $input->utxo->output->locking_script->get_raw_address;

	my $signer = $tx->sign(
		signing_index => $input_index,
		($tree ? (script_tree => $tree) : ()),
	);
	my $sighash = $self->get_all_fields('PSBT_IN_SIGHASH_TYPE', $input_index);
	my $sighash_value = $sighash ? $sighash->value : undef;

	# use transaction signer's ability to give us the signature
	my $signature = $signer->add_signature($key, sighash => $sighash_value)
		->signature->[-1];

	$self->_add_partial_signature_taproot($input_index, $key, $signature, $sighash_value);

	return 1;
}

sub _do_sign_P2TR_scriptpath
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	my $script = $self->get_all_fields('PSBT_IN_TAP_LEAF_SCRIPT', $input_index);
	return 0 unless $script;

	# TODO: detect simple P2MS scripts with checksigadd

	return 1;
}

sub _do_sign_P2TR
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	my $res = $self->_do_sign_P2TR_scriptpath($key, $tx, $input, $input_index);
	$res = $self->_do_sign_P2TR_keypath($key, $tx, $input, $input_index)
		unless $res;

	return $res;
}

sub _do_sign
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	# custom script - unsupported
	my $type = $input->utxo->output->locking_script->type;
	return 0 unless defined $type;

	# some types are defined but unsupported (P2PK, nulldata)
	my $method = $self->can("_do_sign_$type");
	return 0 unless $method;

	return $self->$method($key, $tx, $input, $input_index);
}

signature_for sign => (
	method => !!1,
	positional => [
		InstanceOf ['Bitcoin::Crypto::Key::Private']
	],
);

sub sign
{
	my ($self, $key) = @_;
	my $tx = $self->get_transaction;
	my $inputs = $tx->inputs;

	my $public_hash = $key->get_public_key->get_hash;
	my $signed = 0;
	foreach my $input_index (0 .. $#{$inputs}) {
		my @sigs = $self->get_all_fields('PSBT_IN_PARTIAL_SIG', $input_index);
		next if any { $_->key->get_hash eq $public_hash } @sigs;

		$signed += $self->_do_sign($key, $tx, $inputs->[$input_index], $input_index);
	}

	return $signed;
}

1;

