use Test2::V0;
use Bitcoin::Crypto qw(btc_psbt btc_transaction);
use Bitcoin::Crypto::Constants qw(:transaction);
use Bitcoin::Crypto::Util qw(to_format);

################################################################################
# This tests for integration of PSBTs with other parts of Bitcoin::Crypto
################################################################################

# NOTE: segwit transaction, signatures do not affect hash
my $expected_minimal = '866caf39ed25aaf2b8a61eba9cecffc5a258275879935454c743ad7fee73d09e';
my $minimal_hex =
	'0200000000010151f687ad557af0ea4833bc2124e9fd0f8b54642ca308e7ad609383e42a01391d0000000000fdffffff01684c030000000000160014c6d14eae8a0e593ae7f358f29255f2a3932090300140dfb73d96c1056dddb0240225ca75658bcb99ed9101240bd7d672ad1cf512709bc1d0c2ea0e28d01342c7359e47f86071344ad70ee5871ac6d5d7625726a7909500000000';

my @minimal_v0 = (
	{
		type => 'PSBT_GLOBAL_UNSIGNED_TX',
		value => btc_transaction->new(version => 2)
			->add_input(
				utxo => [[hex => '1d39012ae4839360ade708a32c64548b0ffde92421bc3348eaf07a55ad87f651'], 0],
				sequence_no => RBF_SEQUENCE_NO_THRESHOLD,
			)
			->add_output(
				locking_script => [address => 'bc1qcmg5at52pevn4elntrefy40j5wfjpypsxvuamf'],
				value => 216168,
			),
	},
);

my @minimal_v2 = (
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
		value => 216168,
	},
	{
		type => 'PSBT_OUT_SCRIPT',
		index => 0,
		value => [address => 'bc1qcmg5at52pevn4elntrefy40j5wfjpypsxvuamf'],
	},
);

subtest 'should build valid transaction from minimal psbt' => sub {
	is to_format [hex => build_psbt(@minimal_v0)->get_transaction->txid], $expected_minimal, 'psbtv0 ok';
	is to_format [hex => build_psbt(@minimal_v2)->get_transaction->txid], $expected_minimal, 'psbtv2 ok';
};

subtest 'should build valid transaction with final signatures' => sub {
	my $tx = btc_transaction->from_serialized([hex => $minimal_hex]);

	my $psbt = build_psbt(
		@minimal_v0,
		{
			type => 'PSBT_IN_FINAL_SCRIPTWITNESS',
			index => 0,
			value => $tx->inputs->[0]->serialized_witness,
		}
	);

	my $psbt_witness = $psbt->get_transaction->inputs->[0]->witness;
	is $psbt_witness, $tx->inputs->[0]->witness, 'witness ok';
};

subtest 'should return valid height-based locktime from version 2 based on input' => sub {
	my $psbt = build_psbt(
		@minimal_v2,
		{
			type => 'PSBT_IN_REQUIRED_HEIGHT_LOCKTIME',
			index => 0,
			value => 555,
		}
	);

	is $psbt->get_locktime, 555, 'locktime ok';
};

subtest 'should return valid time-based locktime from version 2 based on input' => sub {
	my $psbt = build_psbt(
		@minimal_v2,
		{
			type => 'PSBT_IN_REQUIRED_TIME_LOCKTIME',
			index => 0,
			value => LOCKTIME_HEIGHT_THRESHOLD + 555,
		}
	);

	is $psbt->get_locktime, LOCKTIME_HEIGHT_THRESHOLD + 555, 'locktime ok';
};

subtest 'should return valid height-based locktime from version 2 based on input (both options)' => sub {
	my $psbt = build_psbt(
		@minimal_v2,
		{
			type => 'PSBT_IN_REQUIRED_HEIGHT_LOCKTIME',
			index => 0,
			value => 555,
		},
		{
			type => 'PSBT_IN_REQUIRED_TIME_LOCKTIME',
			index => 0,
			value => LOCKTIME_HEIGHT_THRESHOLD + 555,
		}
	);

	is $psbt->get_locktime, 555, 'locktime ok';
};

subtest 'should return valid height-based locktime from version 2 based on fallback' => sub {
	my $psbt = build_psbt(
		@minimal_v2,
		{
			type => 'PSBT_GLOBAL_FALLBACK_LOCKTIME',
			value => 555,
		},
	);

	is $psbt->get_locktime, 555, 'locktime ok';
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

