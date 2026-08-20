package Bitcoin::Crypto::Role::PSBT::Signer;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;
use Types::Common -sigs;

use Bitcoin::Crypto qw(btc_script_tree);
use Bitcoin::Crypto::Constants qw(:sighash);
use Bitcoin::Crypto::Transaction::Flags;

sub _input_has_witness_utxo
{
	my ($self, $input_index) = @_;

	my $witness_utxo = $self->get_all_fields('PSBT_IN_WITNESS_UTXO', $input_index);
	return !!$witness_utxo;
}

sub _add_partial_signature
{
	my ($self, $input_index, $key, $signature, $sighash) = @_;

	$self->add_field(
		type => 'PSBT_IN_PARTIAL_SIG',
		index => $input_index,
		key => $key->get_public_key,
		value => $signature,
	);

	if ($self->version == 2) {

		# NOTE: SIGHASH_DEFAULT may not be correct for pre-taproot, but it's only
		# used to set modifiable flags, which will be the same for SIGHASH_ALL
		$sighash = $sighash ? $sighash->value : SIGHASH_ALL;

		my $modifiable = $self->get_all_fields('PSBT_GLOBAL_TX_MODIFIABLE');
		$modifiable //= $self
			->add_field(type => 'PSBT_GLOBAL_TX_MODIFIABLE', value => {})
			->get_field('PSBT_GLOBAL_TX_MODIFIABLE');

		my $value = $modifiable->value;

		if (!($sighash & SIGHASH_ANYONECANPAY)) {
			$value->{inputs_modifiable} = !!0;
		}

		if (!($sighash & SIGHASH_NONE)) {
			$value->{outputs_modifiable} = !!0;
		}

		if (!($sighash & SIGHASH_SINGLE)) {
			$value->{has_sighash_single} = !!1;
		}

		# update the value back in the PSBT
		$modifiable->set_value($value);
	}
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

	$self->_add_partial_signature($input_index, $key, $signature, $sighash);
	return 1;
}

sub _do_sign_P2SH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	# TODO: If a redeemScript is provided, the scriptPubKey must be for that redeemScript

	# TODO: only for normal P2SH (not nested segwit)
	return 0 if $self->_input_has_witness_utxo($input_index);

	# TODO
	return 0;
}

sub _do_sign_P2WPKH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	return 0 unless $key->get_public_key->get_hash eq $input->utxo->output->locking_script->get_raw_address;
	my $signer = $tx->sign(signing_index => $input_index, flags => Bitcoin::Crypto::Transaction::Flags->new_full);
	my $sighash = $self->get_all_fields('PSBT_IN_SIGHASH_TYPE', $input_index);

	# use transaction signer's ability to give us the signature
	my $signature = $signer->add_signature($key, sighash => $sighash ? $sighash->value : undef)
		->signature->[-1];

	$self->_add_partial_signature($input_index, $key, $signature, $sighash);
	return 1;
}

sub _do_sign_P2WSH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

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

	# use transaction signer's ability to give us the signature
	my $signature = $signer->add_signature($key, sighash => $sighash ? $sighash->value : undef)
		->signature->[-1];

	$self->add_field(
		type => 'PSBT_IN_TAP_KEY_SIG',
		index => $input_index,
		value => $signature,
	);

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

	my $method = "_do_sign_$type";
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

	my $is_mine = sub {
		my ($input_index) = @_;
		state $is_ext = $key->isa('Bitcoin::Crypto::Key::ExtPrivate');
	};

	my $signed = 0;
	foreach my $input_index (0 .. $#{$inputs}) {
		$signed += $self->_do_sign($key, $tx, $inputs->[$input_index], $input_index);
	}

	return $signed;
}

1;

