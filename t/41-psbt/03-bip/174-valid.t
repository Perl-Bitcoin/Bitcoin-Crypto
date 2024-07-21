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
		'One P2PKH input. Outputs are empty',
		'cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 2, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
				'af2cac1e0e33d896d9d0751d66fcb2fa54b737c7a13199281fb57e4f497bb652',
				'global tx ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_NON_WITNESS_UTXO', 0)->value->get_hash],
				'f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126',
				'utxo ok';
		},
	],

	[
		'One P2PKH input and one P2SH-P2WPKH input. First input is signed and finalized. Outputs are empty',
		'cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 2, 'input count ok';
			is $psbt->output_count, 2, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
				'fed6cd1fde4db4e13e7e800317e37f9cbd75ec364389670eeff80da993c7e560',
				'global tx ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_FINAL_SCRIPTSIG', 0)->value->get_hash],
				'10c21b57162c0224a893ee7991a9dbb6587a04f7',
				'script sig ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_WITNESS_UTXO', 1)->value->locking_script->get_hash],
				'ac0fa24591d956e8582ab5106018a9d9cf7c257f',
				'utxo script ok';
		},
	],

	[
		'One P2PKH input which has a non-final scriptSig and has a sighash type specified. Outputs are empty',
		'cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA==',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 2, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
				'af2cac1e0e33d896d9d0751d66fcb2fa54b737c7a13199281fb57e4f497bb652',
				'global tx ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_NON_WITNESS_UTXO', 0)->value->get_hash],
				'f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126',
				'utxo ok';

			is $psbt->get_field('PSBT_IN_SIGHASH_TYPE', 0)->value,
				Bitcoin::Crypto::Constants::sighash_all,
				'sighash ok';
		},
	],

	[
		"One P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available. Outputs filled.",
		'cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEA3wIAAAABJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAakcwRAIgcLIkUSPmv0dNYMW1DAQ9TGkaXSQ18Jo0p2YqncJReQoCIAEynKnazygL3zB0DsA5BCJCLIHLRYOUV663b8Eu3ZWzASECZX0RjTNXuOD0ws1G23s59tnDjZpwq8ubLeXcjb/kzjH+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 2, 'input count ok';
			is $psbt->output_count, 2, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
				'fed6cd1fde4db4e13e7e800317e37f9cbd75ec364389670eeff80da993c7e560',
				'global tx ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_NON_WITNESS_UTXO', 0)->value->get_hash],
				'e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab',
				'utxo ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_REDEEM_SCRIPT', 1)->value->get_hash],
				'3545e6e33b832c47050f24d3eeb93c9c03948bc7',
				'redeem script ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_WITNESS_UTXO', 1)->value->locking_script->get_hash],
				'ac0fa24591d956e8582ab5106018a9d9cf7c257f',
				'witness utxo script ok';

			my @bip32 = (
				[
					0,
					'768a40bbd740cbe81d988e71de2a4d5c71396b1d',
					'b4a6ba67',
					[2147483648, 2147483648, 2147483650],
				],
				[
					1,
					'6f4620b553fa095e721b9ee0efe9fa039cca4597',
					'b4a6ba67',
					[2147483648, 2147483649, 2147483650],
				]
			);

			foreach my $case (@bip32) {
				my ($index, $key_hash, $expected_fingerprint, $expected_path) = @{$case};
				my @values = $psbt->get_all_fields('PSBT_OUT_BIP32_DERIVATION', $index);

				is scalar @values, 1, "value count ok for index $index";
				is to_format [hex => $values[0]->key->get_hash],
					$key_hash,
					'key hash ok';

				my ($fingerprint, @path) = @{$values[0]->value};
				is to_format [hex => $fingerprint], $expected_fingerprint, 'fingerprint ok';
				is_deeply \@path, $expected_path, 'path ok';
			}
		},
	],

	[
		"One P2SH-P2WSH input of a 2-of-2 multisig, redeemScript, witnessScript, and keypaths are available. Contains one signature.",
		'cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
				'b4ca8f48572bf08354f8302adfbd9e5c2fc2a52731de5401a39aa048f68c9c21',
				'global tx ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_REDEEM_SCRIPT', 0)->value->get_hash],
				'6345200f68d189e1adc0df1c4d16ea8f14c0dbeb',
				'redeem script ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_WITNESS_SCRIPT', 0)->value->get_hash],
				'981fe8ec333e117bf455b218ad4b0a618cb99db8',
				'redeem script ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_WITNESS_UTXO', 0)->value->locking_script->get_hash],
				'90912582b9f739d70a989796bd3017e6256f9d87',
				'witness utxo script ok';

			my @keys = $psbt->get_all_fields('PSBT_IN_BIP32_DERIVATION', 0);
			my @signatures = $psbt->get_all_fields('PSBT_IN_PARTIAL_SIG', 0);

			is scalar @keys, 2, 'key count ok';
			is scalar @signatures, 1, 'signatures count ok';

			my %data = (
				'3c3e4f3467b6632a7bbc6f5d564cd4deaf6cb521' => [
					'b4a6ba67',
					[2147483648, 2147483648, 2147483652],
					'304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01'
				],
				'38c8ab6e1dc92b031458c197af2ffcbeb83acb4e' => [
					'b4a6ba67',
					[2147483648, 2147483648, 2147483653],
				],
			);

			foreach my $key (@keys) {
				my $hash = to_format [hex => $key->key->get_hash];

				ok exists $data{$hash}, 'key ok';
				my ($expected_fingerprint, $expected_path, $expected_signature) = @{$data{$hash}};

				my ($fingerprint, @path) = @{$key->value};
				is to_format [hex => $fingerprint], $expected_fingerprint, 'fingerprint ok';
				is_deeply \@path, $expected_path, 'path ok';

				if ($expected_signature) {
					my $signature = first { $_->raw_key eq $key->raw_key } @signatures;

					ok defined $signature, 'signature present ok';
					is to_format [hex => $signature->value], $expected_signature, 'signature ok';
				}
			}

		},
	],

	[
		"One P2WSH input of a 2-of-2 multisig. witnessScript, keypaths, and global xpubs are available. Contains no signatures. Outputs filled.",
		'cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA',
	],

	[
		"Unknown types in the inputs.",
		'cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAA=',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
				'75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115',
				'global tx ok';
		},
	],

	[
		"`PSBT_GLOBAL_XPUB`",
		'cHNidP8BAJ0BAAAAAnEOp2q0XFy2Q45gflnMA3YmmBgFrp4N/ZCJASq7C+U1AQAAAAD/////GQmU1qizyMgsy8+y+6QQaqBmObhyqNRHRlwNQliNbWcAAAAAAP////8CAOH1BQAAAAAZdqkUtrwsDuVlWoQ9ea/t0MzD991kNAmIrGBa9AUAAAAAFgAUEYjvjkzgRJ6qyPsUHL9aEXbmoIgAAAAATwEEiLIeA55TDKyAAAAAPbyKXJdp8DGxfnf+oVGGAyIaGP0Y8rmlTGyMGsdcvDUC8jBYSxVdHH8c1FEgplPEjWULQxtnxbLBPyfXFCA3wWkQJ1acUDEAAIAAAACAAAAAgAABAR8A4fUFAAAAABYAFDO5gvkbKPFgySC0q5XljOUN2jpKIgIDMJaA8zx9446mpHzU7NZvH1pJdHxv+4gI7QkDkkPjrVxHMEQCIC1wTO2DDFapCTRL10K2hS3M0QPpY7rpLTjnUlTSu0JFAiAthsQ3GV30bAztoITyopHD2i1kBw92v5uQsZXn7yj3cgEiBgMwloDzPH3jjqakfNTs1m8fWkl0fG/7iAjtCQOSQ+OtXBgnVpxQMQAAgAAAAIAAAACAAAAAAAEAAAAAAQEfAOH1BQAAAAAWABQ4j7lEMH63fvRRl9CwskXgefAR3iICAsd3Fh9z0LfHK57nveZQKT0T8JW8dlatH1Jdpf0uELEQRzBEAiBMsftfhpyULg4mEAV2ElQ5F5rojcqKncO6CPeVOYj6pgIgUh9JynkcJ9cOJzybFGFphZCTYeJb4nTqIA1+CIJ+UU0BIgYCx3cWH3PQt8crnue95lApPRPwlbx2Vq0fUl2l/S4QsRAYJ1acUDEAAIAAAACAAAAAgAAAAAAAAAAAAAAiAgLSDKUC7iiWhtIYFb1DqAY3sGmOH7zb5MrtRF9sGgqQ7xgnVpxQMQAAgAAAAIAAAACAAAAAAAQAAAAA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 2, 'input count ok';
			is $psbt->output_count, 2, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value->get_hash],
				'eb685b6890fa2a47ac962afdfccb4159e99819c4537616f842dd9eb745ff62b1',
				'global tx ok';

			my $xpub = $psbt->get_field('PSBT_GLOBAL_XPUB');
			my $xpub_key = $xpub->key;
			my ($xpub_fingerprint, @xpub_path) = @{$xpub->value};
			is to_format [hex => $xpub_key->get_fingerprint], 'a0c1121e', 'xpub fingerprint ok';
			is to_format [hex => $xpub_fingerprint], '27569c50', 'fingerprint ok';
			is_deeply \@xpub_path, [2147483697, 2147483648, 2147483648], 'path ok';
		},
	],

	[
		"0 inputs",
		'cHNidP8BAAoAAAAAAAAAAAAAAA==',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 0, 'input count ok';
			is $psbt->output_count, 0, 'output count ok';
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

