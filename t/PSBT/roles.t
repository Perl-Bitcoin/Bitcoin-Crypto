use Test2::V0;
use Bitcoin::Crypto qw(btc_transaction btc_prv btc_psbt btc_script_tree);
use Bitcoin::Crypto::Constants qw(:transaction :sighash);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Transaction::Output;

################################################################################
# This tests PSBT-specific roles
################################################################################

my $priv = btc_prv->from_serialized("\x01" x 32);
my $fake_txid = [hex => '1d350125e4839360ade708a32c64548b0ffde92421bc3348eaf07a55ad875651'];

my @fields = (
	{
		type => 'PSBT_GLOBAL_VERSION',
		value => 2,
	},
	{
		type => 'PSBT_GLOBAL_TX_VERSION',
		value => 2,
	},
	{
		type => 'PSBT_GLOBAL_OUTPUT_COUNT',
		value => 1,
	},
	{
		type => 'PSBT_OUT_AMOUNT',
		index => 0,
		value => 10_000,
	},
	{
		type => 'PSBT_OUT_SCRIPT',
		index => 0,
		value => [address => $priv->get_public_key->get_taproot_address],
	},
);

subtest 'should sign and set final signatures when finalizing P2PKH input' => sub {
	my $utxo_tx = btc_transaction->new;

	# utxo input is mandatory, so make a fake one
	$utxo_tx->add_input(
		utxo => [$fake_txid, 0],
	);

	# utxo output will be used for signing
	$utxo_tx->add_output(
		value => 10_000,
		locking_script => [address => $priv->get_public_key->get_legacy_address],
	);

	my $psbt = build_psbt(
		[[$utxo_tx->get_hash, 0]],
		@fields,
		{
			type => 'PSBT_IN_NON_WITNESS_UTXO',
			index => 0,
			value => $utxo_tx,
		},
	);

	is $psbt->sign($priv), 1, 'an input was signed';
	check_modifiable($psbt);
	$psbt->finalize;

	ok lives { $psbt->get_transaction->verify }, 'verification passed';
};

subtest 'should sign and set final signatures when finalizing P2SH(P2WPKH) input' => sub {
	my $psbt = build_psbt(
		[[$fake_txid, 0]],
		@fields,
		{
			type => 'PSBT_IN_WITNESS_UTXO',
			index => 0,
			value => Bitcoin::Crypto::Transaction::Output->new(
				value => 10_000,
				locking_script => [address => $priv->get_public_key->get_compat_address],
			),
		},
		{
			type => 'PSBT_IN_REDEEM_SCRIPT',
			index => 0,
			value => $priv->get_public_key->witness_program,
		},
	);

	is $psbt->sign($priv), 1, 'an input was signed';
	check_modifiable($psbt);
	$psbt->finalize;

	ok lives { $psbt->get_transaction->verify }, 'verification passed';
};

subtest 'should sign and set final signatures when finalizing P2WPKH input' => sub {
	my $psbt = build_psbt(
		[[$fake_txid, 0]],
		@fields,
		{
			type => 'PSBT_IN_WITNESS_UTXO',
			index => 0,
			value => Bitcoin::Crypto::Transaction::Output->new(
				value => 10_000,
				locking_script => [address => $priv->get_public_key->get_segwit_address],
			),
		},
	);

	is $psbt->sign($priv), 1, 'an input was signed';
	check_modifiable($psbt);
	$psbt->finalize;

	ok lives { $psbt->get_transaction->verify }, 'verification passed';
};

subtest 'should sign and set final signatures when finalizing P2TR key input' => sub {
	my $fake_merkle_root = [hex => "1d358125e4839360ade708a32c64548b0ffde92421bc3348eaf07a55ad775651"];
	my $tree = btc_script_tree->new(tree => [{hash => $fake_merkle_root}]);

	my $psbt = build_psbt(
		[[$fake_txid, 0], [$fake_txid, 1]],
		@fields,
		{
			type => 'PSBT_IN_WITNESS_UTXO',
			index => 0,
			value => Bitcoin::Crypto::Transaction::Output->new(
				value => 5000,
				locking_script => [address => $priv->get_public_key->get_taproot_address],
			),
		},
		{
			type => 'PSBT_IN_WITNESS_UTXO',
			index => 1,
			value => Bitcoin::Crypto::Transaction::Output->new(
				value => 5000,
				locking_script => [address => $priv->get_public_key->get_taproot_address($tree)],
			),
		},
		{
			type => 'PSBT_IN_TAP_MERKLE_ROOT',
			index => 1,
			value => $fake_merkle_root,
		},
	);

	is $psbt->sign($priv), 2, 'both inputs were signed';
	check_modifiable($psbt);
	$psbt->finalize;

	ok lives { $psbt->get_transaction->verify }, 'verification passed';
};

subtest 'should do nothing when calling sign twice' => sub {
	my $psbt = build_psbt(
		[[$fake_txid, 0]],
		@fields,
		{
			type => 'PSBT_IN_WITNESS_UTXO',
			index => 0,
			value => Bitcoin::Crypto::Transaction::Output->new(
				value => 10_000,
				locking_script => [address => $priv->get_public_key->get_segwit_address],
			),
		},
	);

	is $psbt->sign($priv), 1, 'an input was signed';
	is $psbt->sign($priv), 0, 'no inputs signed a second time';
};

subtest 'should combine two PSBTs' => sub {
	my $psbt1 = build_psbt(
		[[$fake_txid, 0]],
		@fields,
		{
			type => 'PSBT_IN_WITNESS_UTXO',
			index => 0,
			value => Bitcoin::Crypto::Transaction::Output->new(
				value => 10_000,
				locking_script => [address => $priv->get_public_key->get_segwit_address],
			),
		},
	);

	my $psbt2 = build_psbt(
		[[$fake_txid, 0]],
		@fields,
		{
			type => 'PSBT_IN_SIGHASH_TYPE',
			index => 0,
			value => SIGHASH_ALL | SIGHASH_ANYONECANPAY,
		},
	);

	my $combined = $psbt1->combine($psbt2);
	ok $combined != $psbt1 && $combined != $psbt2, 'new psbt created';

	my @fields = $combined->list_fields;
	is [map { [$_->[0]->name, $_->[1]] } @fields],
		[
			['PSBT_GLOBAL_INPUT_COUNT', undef],
			['PSBT_GLOBAL_VERSION', undef],
			['PSBT_GLOBAL_TX_VERSION', undef],
			['PSBT_GLOBAL_OUTPUT_COUNT', undef],
			['PSBT_IN_PREVIOUS_TXID', 0],
			['PSBT_IN_OUTPUT_INDEX', 0],
			['PSBT_IN_WITNESS_UTXO', 0],
			['PSBT_IN_SIGHASH_TYPE', 0],
			['PSBT_OUT_AMOUNT', 0],
			['PSBT_OUT_SCRIPT', 0],
		],
		'fields ok';

	my $utxo_value = $combined->get_field('PSBT_IN_WITNESS_UTXO', 0)->value;
	is $utxo_value->locking_script->get_address, $priv->get_public_key->get_segwit_address,
		'PSBT_IN_WITNESS_UTXO ok';

	my $sighash_value = $combined->get_field('PSBT_IN_SIGHASH_TYPE', 0)->value;
	is $sighash_value, SIGHASH_ALL | SIGHASH_ANYONECANPAY, 'PSBT_IN_SIGHASH_TYPE ok';
};

# TODO: check combining MODIFIABLE

done_testing;

sub build_psbt
{
	my $inputs = shift;
	my $psbt = btc_psbt->new;

	$psbt->add_field(
		type => 'PSBT_GLOBAL_INPUT_COUNT',
		value => scalar @$inputs,
	);

	foreach my $input_index (0 .. $#$inputs) {
		my ($txid, $output_index) = @{$inputs->[$input_index]};

		$psbt->add_field(
			type => 'PSBT_IN_PREVIOUS_TXID',
			index => $input_index,
			value => $txid,
		);

		$psbt->add_field(
			type => 'PSBT_IN_OUTPUT_INDEX',
			index => $input_index,
			value => $output_index,
		);
	}

	foreach my $field (@_) {
		$psbt->add_field(%$field);
	}

	return $psbt;
}

sub check_modifiable
{
	my ($psbt, $sighash) = @_;
	$sighash //= SIGHASH_ALL;

	my %expected = (
		inputs_modifiable => !!($sighash & SIGHASH_ANYONECANPAY),
		outputs_modifiable => ($sighash & 31) == SIGHASH_NONE,
		has_sighash_single => ($sighash & 31) == SIGHASH_SINGLE,
	);

	$expected{raw_value} =
		($expected{inputs_modifiable} & 0x01)
		| ($expected{outputs_modifiable} & 0x02)
		| ($expected{has_sighash_single} & 0x04)
		;

	my $modifiable = $psbt->get_all_fields('PSBT_GLOBAL_TX_MODIFIABLE');
	my $value = $modifiable ? $modifiable->value : undef;

	is $value, \%expected, 'PSBT_GLOBAL_TX_MODIFIABLE status ok';
}

