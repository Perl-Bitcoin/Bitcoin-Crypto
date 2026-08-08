use Test2::V0;
use Bitcoin::Crypto qw(btc_transaction btc_prv btc_psbt);
use Bitcoin::Crypto::Constants qw(:transaction);
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
	$psbt->finalize;

	ok lives { $psbt->get_transaction->verify }, 'verification passed';
};

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

