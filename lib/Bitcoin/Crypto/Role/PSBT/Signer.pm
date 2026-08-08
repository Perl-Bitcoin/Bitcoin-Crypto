package Bitcoin::Crypto::Role::PSBT::Signer;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;
use Types::Common -sigs;

use Bitcoin::Crypto qw(btc_script_tree);

sub _add_partial_signature
{
	my ($self, $input_index, $key, $signature) = @_;

	$self->add_field(
		type => 'PSBT_IN_PARTIAL_SIG',
		index => $input_index,
		key => $key->get_public_key,
		value => $signature,
	);
}

sub _do_sign_P2PKH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	return 0 unless $key->get_public_key->get_hash eq $input->utxo->output->locking_script->get_raw_address;
	my $signer = $tx->sign(signing_index => $input_index);
	my $sighash = $self->get_all_fields('PSBT_IN_SIGHASH_TYPE', $input_index);

	# use transaction signer's ability to give us the signature
	my $signature = $signer->add_signature($key, sighash => $sighash ? $sighash->value : undef)
		->signature->[-1];

	$self->_add_partial_signature($input_index, $key, $signature);
	return 1;
}

sub _do_sign_P2SH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	# TODO
	return 0;
}

sub _do_sign_P2WPKH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

	return $self->_do_sign_P2PKH($key, $tx, $input, $input_index);
}

sub _do_sign_P2WSH
{
	my ($self, $key, $tx, $input, $input_index) = @_;

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
		(InstanceOf ['Bitcoin::Crypto::Key::Private'])
			| (InstanceOf ['Bitcoin::Crypto::Key::ExtPrivate']),
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

	# TODO: add PSBT_IN_PARTIAL_SIG to inputs
	# TODO: how to check if the input is ours?
	# TODO: use PSBT_IN_BIP32_DERIVATION to locate the key
	# TODO: create a signer and sign each type
	# TODO: BIP170 checks:
	# If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
	# If a witness UTXO is provided, no non-witness signature may be created
	# If a redeemScript is provided, the scriptPubKey must be for that redeemScript
	# If a witnessScript is provided, the scriptPubKey or the redeemScript must be for that witnessScript
	# If a sighash type is provided, the signer must check that the sighash is acceptable. If unacceptable, they must fail.
	# If a sighash type is not provided, the signer should sign using SIGHASH_ALL, but may use any sighash type they wish.
	# TODO: this note
	# For PSBTv2s, a signer must update the PSBT_GLOBAL_TX_MODIFIABLE field after signing inputs so that it accurately reflects the state of the PSBT. If the Signer added a signature that does not use SIGHASH_ANYONECANPAY, the Input Modifiable flag must be set to False. If the Signer added a signature that does not use SIGHASH_NONE, the Outputs Modifiable flag must be set to False. If the Signer added a signature that uses SIGHASH_SINGLE, the Has SIGHASH_SINGLE flag must be set to True.
}

1;

