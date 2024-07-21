use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use List::Util qw(first);

use Bitcoin::Crypto qw(btc_psbt);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# get rid of non-bitcoin networks which make it hard to run these tests
foreach my $network_id (Bitcoin::Crypto::Network->find(sub { shift->id !~ m{^bitcoin} })) {
	Bitcoin::Crypto::Network->get($network_id)->unregister;
}

my @cases = (
	[
		'1 input, 2 output PSBTv2, required fields only.',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;
			is $psbt->version, 2, 'version ok';
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 2, 'output count ok';
			is $psbt->get_field('PSBT_GLOBAL_TX_VERSION')->value, 2, 'tx version ok';

			is $psbt->get_field('PSBT_IN_OUTPUT_INDEX', 0)->value, 0, 'utxo index ok';
			is to_format [hex => $psbt->get_field('PSBT_IN_PREVIOUS_TXID', 0)->value],
				'c85f81844094f9f0eec1e41f8d63e0a99e9f73dc725d7319871c9c4121d90a0b', 'utxo txid ok';

			is $psbt->get_field('PSBT_OUT_AMOUNT', 0)->value, 800000000, 'output 0 amount ok';
			is to_format [hex => $psbt->get_field('PSBT_OUT_SCRIPT', 0)->value->to_serialized],
				'0014c430f64c4756da310dbd1a085572ef299926272c', 'output 0 script ok';

			is $psbt->get_field('PSBT_OUT_AMOUNT', 1)->value, 199998859, 'output 1 amount ok';
			is to_format [hex => $psbt->get_field('PSBT_OUT_SCRIPT', 1)->value->to_serialized],
				'00144dd193ac964a56ac1b9e1cca8454fe2f474f8513', 'output 1 script ok';

		},
	],

	[
		'1 input, 2 output updated PSBTv2.',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';

			my $utxo_tx = $psbt->get_field('PSBT_IN_NON_WITNESS_UTXO', 0)->value;
			my $utxo_txid = $psbt->get_field('PSBT_IN_PREVIOUS_TXID', 0)->value;
			my $utxo_index = $psbt->get_field('PSBT_IN_OUTPUT_INDEX', 0)->value;
			my $utxo_output = $psbt->get_field('PSBT_IN_WITNESS_UTXO', 0)->value;

			is to_format [hex => $utxo_txid], to_format [hex => $utxo_tx->get_hash], 'utxo txid ok';

			my $output = $utxo_tx->outputs->[$utxo_index];
			is to_format [hex => $output->to_serialized], to_format [hex => $utxo_output->to_serialized],
				'utxo outputs ok';

			is $output->value, 999999000, 'utxo value ok';
			is to_format [hex => $output->locking_script->to_serialized],
				'0014b0a3af144208412693ca7d166852b52db0aef06e', 'utxo script ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE.',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';

			is $psbt->get_field('PSBT_IN_SEQUENCE', 0)->value, Bitcoin::Crypto::Constants::max_sequence_no - 1,
				'sequence ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE, and all locktime fields',
		'cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8BEQSMjcRiARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';

			is $psbt->get_field('PSBT_GLOBAL_FALLBACK_LOCKTIME')->value, 0, 'global fallback locktime ok';
			is $psbt->get_field('PSBT_IN_REQUIRED_HEIGHT_LOCKTIME', 0)->value, 10000, 'height locktime ok';
			is $psbt->get_field('PSBT_IN_REQUIRED_TIME_LOCKTIME', 0)->value, 1657048460, 'time locktime ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with Inputs Modifiable Flag (bit 0) of PSBT_GLOBAL_TX_MODIFIABLE set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEBAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 1,
				inputs_modifiable => !!1,
				outputs_modifiable => !!0,
				has_sighash_single => !!0,
				},
				'modifiable flags ok';

			my $initial_raw = $flags->raw_value;
			$flags->set_value($flags->value);
			is to_format [hex => $flags->raw_value], to_format [hex => $initial_raw], 'flags updated ok';

			$flags->set_value({outputs_modifiable => 1, has_sighash_single => 1});
			is to_format [hex => $flags->raw_value], '06', 'flags updated to custom ok';

			# cleanup after modification
			$flags->set_raw_value($initial_raw);
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with Outputs Modifiable Flag (bit 1) of PSBT_GLOBAL_TX_MODIFIABLE set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 2,
				inputs_modifiable => !!0,
				outputs_modifiable => !!1,
				has_sighash_single => !!0,
				},
				'modifiable flags ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with Has SIGHASH_SINGLE Flag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEEAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 4,
				inputs_modifiable => !!0,
				outputs_modifiable => !!0,
				has_sighash_single => !!1,
				},
				'modifiable flags ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with an undefined flag (bit 3) of PSBT_GLOBAL_TX_MODIFIABLE set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEIAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 8,
				inputs_modifiable => !!0,
				outputs_modifiable => !!0,
				has_sighash_single => !!0,
				},
				'modifiable flags ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with both Inputs Modifiable Flag (bit 0) and Outputs Modifiable Flag (bit 1) of PSBT_GLOBAL_TX_MODIFIABLE set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEDAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 3,
				inputs_modifiable => !!1,
				outputs_modifiable => !!1,
				has_sighash_single => !!0,
				},
				'modifiable flags ok';

			# check serialization after setting value
			$flags->set_value(
				{
					inputs_modifiable => 1,
					outputs_modifiable => 1,
				}
			);
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with both Inputs Modifiable Flag (bit 0) and Has SIGHASH_SINGLE Flag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEFAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 5,
				inputs_modifiable => !!1,
				outputs_modifiable => !!0,
				has_sighash_single => !!1,
				},
				'modifiable flags ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with both Outputs Modifiable Flag (bit 1) and Has SIGHASH_SINGLE FLag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEGAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 6,
				inputs_modifiable => !!0,
				outputs_modifiable => !!1,
				has_sighash_single => !!1,
				},
				'modifiable flags ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with all defined PSBT_GLOBAL_TX_MODIFIABLE flags set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEHAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 7,
				inputs_modifiable => !!1,
				outputs_modifiable => !!1,
				has_sighash_single => !!1,
				},
				'modifiable flags ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with all possible PSBT_GLOBAL_TX_MODIFIABLE flags set',
		'cHNidP8BAgQCAAAAAQQBAQEFAQIBBgH/AfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==',
		sub {
			my $psbt = shift;

			my $flags = $psbt->get_field('PSBT_GLOBAL_TX_MODIFIABLE');
			is_deeply $flags->value, {
				raw_value => 255,
				inputs_modifiable => !!1,
				outputs_modifiable => !!1,
				has_sighash_single => !!1,
				},
				'modifiable flags ok';
		},
	],

	[
		'1 input, 2 output updated PSBTv2, with all PSBTv2 fields',
		'cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAQYBBwH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BDiALCtkhQZwchxlzXXLcc5+eqeBjjR/kwe7w+ZRAhIFfyAEPBAAAAAABEAT+////AREEjI3EYgESBBAnAAAAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAABBBYAFMQw9kxHVtoxDb0aCFVy7ymZJicsACICAuNvv/U91TQHDPj9OWYUaA81epuF23NAvxz6dF0q17NAGPadhz5UAACAAQAAgAAAAIABAAAAZAAAAAEDCIu96wsAAAAAAQQWABRN0ZOslkpWrBueHMqEVP4vR0+FEwA=',
		sub {
			my $psbt = shift;

			# this is a good place to check serialization / deserialization of each PSBT key
			foreach my $map (@{$psbt->maps}) {
				foreach my $field (@{$map->fields}) {
					my $name = $field->type->name;

					my $initial_value = $field->raw_value;
					$field->set_value($field->value);

					is to_format [hex => $field->raw_value], to_format [hex => $initial_value],
						"field $name value ok";

					if ($field->type->has_key_data) {
						my $initial_key = $field->raw_key;
						$field->set_key($field->key);

						is to_format [hex => $field->raw_key], to_format [hex => $initial_key],
							"field $name key ok";
					}
				}
			}
		},
	],

);

foreach my $case (@cases) {
	my ($name, $base64, $checker) = @{$case};

	subtest $name => sub {
		my $psbt;
		lives_ok {
			$psbt = btc_psbt->from_serialized([base64 => $base64]);
		} 'deserialization ok';

		$checker->($psbt) if $checker;
		is to_format [base64 => $psbt->to_serialized], $base64, 'serialized again ok';
	};
}

done_testing;

