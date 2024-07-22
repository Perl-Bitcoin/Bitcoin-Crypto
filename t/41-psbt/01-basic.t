use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_psbt btc_transaction);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::PSBT::Field;

subtest 'should allow creation of a version 0 PSBT' => sub {
	my $psbt = btc_psbt->new;

	dies_ok { $psbt->check } 'check on empty ok';
};

subtest 'should be able to add new fields' => sub {
	my $psbt = btc_psbt->new;

	my $tx = btc_transaction->new;

	$tx->add_input(
		utxo => [[hex => 'e120db2fb51aa1a698d1096201dcf6e87a7dade39db94abbc1a4d7ea5afb7564'], 1]
	);

	$tx->add_output(
		value => 1234,
		locking_script => [address => 'bc1pjex5vx48metd6xhp20uqdn3dqzwdrnnmzgmpur0mlzys9urgcshs4wmvut'],
	);

	$psbt->add_field(
		type => 'PSBT_GLOBAL_UNSIGNED_TX',
		value => $tx,
	);

	lives_ok { $psbt->check } 'check ok';

	is $psbt->input_count, 1, 'input count ok';
	is $psbt->output_count, 1, 'output count ok';

	# check if we are able to get a field from an input
	lives_and {
		my @sigs = $psbt->get_all_fields('PSBT_IN_PARTIAL_SIG', 0);
		is scalar @sigs, 0, 'no sigs ok';
	};
};

subtest 'should allow creation of a version 2 PSBT' => sub {
	my $psbt = btc_psbt->new;

	my @fields = (
		{
			type => 'PSBT_GLOBAL_VERSION',
			value => 2,
		},
		{
			type => 'PSBT_GLOBAL_TX_VERSION',
			value => 0,
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
			value => [hex => 'e120db2fb51aa1a698d1096201dcf6e87a7dade39db94abbc1a4d7ea5afb7564'],
			index => 0,
			check => sub {
				return (
					to_format [hex => shift],
					'e120db2fb51aa1a698d1096201dcf6e87a7dade39db94abbc1a4d7ea5afb7564'
				);
			},
		},
		{
			type => 'PSBT_IN_OUTPUT_INDEX',
			value => 1,
			index => 0,
		},
		{
			type => 'PSBT_OUT_AMOUNT',
			value => 1234,
			index => 0,
		},
		{
			type => 'PSBT_OUT_SCRIPT',
			value => [address => 'bc1pjex5vx48metd6xhp20uqdn3dqzwdrnnmzgmpur0mlzys9urgcshs4wmvut'],
			index => 0,
			check => sub {
				return (
					shift->get_address,
					'bc1pjex5vx48metd6xhp20uqdn3dqzwdrnnmzgmpur0mlzys9urgcshs4wmvut'
				);
			},
		},
	);

	foreach my $field (@fields) {
		my $check = delete $field->{check};
		$psbt->add_field(%$field);

		my $value = $psbt->get_field($field->{type}, $field->{index})->value;
		my $expected = $field->{value};
		if ($check) {
			($value, $expected) = $check->($value);
		}
		is $value, $expected, "value roundtrip for $field->{type} ok";
	}

	lives_and {
		is to_format [base64 => $psbt->to_serialized],
			'cHNidP8BAgQAAAAAAQQBAQEFAQEB+wQCAAAAAAEOIGR1+1rq16TBu0q5neOtfXro9twBYgnRmKahGrUv2yDhAQ8EAQAAAAABAwjSBAAAAAAAAAEEIlEglk1GGqfeVt0a4VP4Bs4tAJzRznsSNh4N+/iJAvBoxC8A',
			'serialized psbt ok';
	};
};

done_testing;

