use Test2::V0;
use Bitcoin::Crypto qw(btc_psbt btc_transaction btc_script_tree btc_tapscript);
use Bitcoin::Crypto::Util qw(to_format pack_compactsize);
use Bitcoin::Crypto::Constants qw(:psbt :transaction :script);
use Bitcoin::Crypto::PSBT::Field;
use Bitcoin::Crypto::PSBT::FieldType;

my $minimal_tx = btc_transaction->new(version => 2)
	->add_input(
		utxo => [[hex => '1d39012ae4839360ade708a32c64548b0ffde92421bc3348eaf07a55ad87f651'], 0],
		sequence_no => RBF_SEQUENCE_NO_THRESHOLD,
	)
	->add_output(
		locking_script => [address => 'bc1qcmg5at52pevn4elntrefy40j5wfjpypsxvuamf'],
		value => 216168,
	);

my $minimal_tx_hex = to_format [hex => $minimal_tx->to_serialized];
my $minimal_tx_hex_len = to_format [hex => pack_compactsize(length($minimal_tx_hex) / 2)];

subtest 'should disallow maps without a final separator' => sub {
	my $erroneous = (to_format [hex => PSBT_MAGIC])
		. "0100${minimal_tx_hex_len}${minimal_tx_hex}00"
		. "00"
		. "01000152";    # NOTE: no final zero here

	my $ex = dies { btc_psbt->from_serialized([hex => $erroneous]); };
	isa_ok $ex, 'Bitcoin::Crypto::Exception::PSBT';
	like $ex, qr{serialized map data is corrupted}, 'exception full ok';
};

subtest 'should allow MODIFIABLE to change the value without changing raw value' => sub {
	my $field = Bitcoin::Crypto::PSBT::Field->new(
		type => 'PSBT_GLOBAL_TX_MODIFIABLE',
		value => {
			inputs_modifiable => !!1,
		},
	);

	my $value = $field->value;
	$value->{inputs_modifiable} = !!0;
	$field->set_value($value);

	is $field->value->{inputs_modifiable}, !!0, 'can modify PSBT_GLOBAL_TX_MODIFIABLE ok';
};

subtest 'should correctly handle deep TAP_TREE fields' => sub {
	my $tree = btc_script_tree->new(
		tree => [
			[
				{
					script => btc_tapscript->new->add('OP_1'),
					leaf_version => TAPSCRIPT_LEAF_VERSION,
				},
				{
					script => btc_tapscript->new->add('OP_2'),
					leaf_version => TAPSCRIPT_LEAF_VERSION,
				},
			],
			[
				[
					{
						script => btc_tapscript->new->add('OP_3'),
						leaf_version => TAPSCRIPT_LEAF_VERSION,
					},
					[
						{
							script => btc_tapscript->new->add('OP_4'),
							leaf_version => TAPSCRIPT_LEAF_VERSION,
						},
						{
							script => btc_tapscript->new->add('OP_5'),
							leaf_version => TAPSCRIPT_LEAF_VERSION,
						},
					],
				],
				{
					script => btc_tapscript->new->add('OP_6'),
					leaf_version => TAPSCRIPT_LEAF_VERSION,
				},
			],
		]
	);

	my $field = Bitcoin::Crypto::PSBT::Field->new(
		type => 'PSBT_OUT_TAP_TREE',
		value => $tree,
	);

	my $tree2 = $field->value;
	ok $tree2 != $tree, 'not the same tree object ok';
	is $tree2->get_merkle_root, $tree->get_merkle_root, 'trees ok';
};

subtest 'should return field list in a correct order' => sub {
	my $psbt = btc_psbt->new;

	$psbt->add_field(
		type => 'PSBT_OUT_SCRIPT',
		index => 1,
		value => btc_tapscript->new->add('OP_1'),
	);

	$psbt->add_field(
		type => 'PSBT_OUT_AMOUNT',
		index => 0,
		value => 32767,
	);

	$psbt->add_field(
		type => 'PSBT_IN_SEQUENCE',
		index => 0,
		value => 32767,
	);

	$psbt->add_field(
		type => 'PSBT_IN_OUTPUT_INDEX',
		index => 1,
		value => 5,
	);

	$psbt->add_field(
		type => 'PSBT_GLOBAL_TX_VERSION',
		value => 2,
	);

	my $_f = sub {
		Bitcoin::Crypto::PSBT::FieldType->get_field_by_name(shift);
	};

	is [$psbt->list_fields], [
		[$_f->('PSBT_GLOBAL_TX_VERSION'), undef],
		[$_f->('PSBT_IN_SEQUENCE'), 0],
		[$_f->('PSBT_IN_OUTPUT_INDEX'), 1],
		[$_f->('PSBT_OUT_AMOUNT'), 0],
		[$_f->('PSBT_OUT_SCRIPT'), 1],
		],
		'field list ok';
};

subtest 'should refuse to combine less than two PSBTs' => sub {
	my $psbt = btc_psbt->new;
	my $ex;

	$ex = dies { $psbt->combine() };
	isa_ok $ex, 'Bitcoin::Crypto::Exception::PSBT';
	like $ex, qr{need at least two PSBTs};

	$ex = dies { btc_psbt->combine($psbt) };
	isa_ok $ex, 'Bitcoin::Crypto::Exception::PSBT';
	like $ex, qr{need at least two PSBTs};
};

done_testing;

