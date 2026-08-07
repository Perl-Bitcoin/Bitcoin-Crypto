use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_psbt);
use Bitcoin::Crypto::Constants qw(:transaction);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Transaction::Output;

################################################################################
# This tests PSBT-specific roles
################################################################################

my $priv = btc_prv->from_serialized("\x01" x 32);

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
		type => 'PSBT_GLOBAL_INPUT_COUNT',
		value => 1,
	},
	{
		type => 'PSBT_GLOBAL_OUTPUT_COUNT',
		value => 1,
	},
	{
		type => 'PSBT_IN_PREVIOUS_TXID',
		index => 0,
		value => [hex => '1d39012ae4839360ade708a32c64548b0ffde92421bc3348eaf07a55ad87f651'],
	},
	{
		type => 'PSBT_IN_OUTPUT_INDEX',
		index => 0,
		value => 0,
	},
	{
		type => 'PSBT_IN_SEQUENCE',
		index => 0,
		value => RBF_SEQUENCE_NO_THRESHOLD,
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
	my $psbt = build_psbt(
		@fields,
		{
			type => 'PSBT_IN_WITNESS_UTXO',
			index => 0,
			value => Bitcoin::Crypto::Transaction::Output->new(
				value => 10_000,
				locking_script => [address => $priv->get_public_key->get_legacy_address],
			),
		}
	);

	is $psbt->sign($priv), 1, 'an input was signed';
	$psbt->finalize;

	ok lives { $psbt->get_transaction->verify }, 'verification passed';
};

done_testing;

sub build_psbt
{
	my $psbt = btc_psbt->new;

	foreach my $field (@_) {
		$psbt->add_field(%$field);
	}

	return $psbt;
}

