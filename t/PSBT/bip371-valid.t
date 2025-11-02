use Test2::V0;
use List::Util qw(first);
use Bitcoin::Crypto qw(btc_psbt btc_script_tree);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# get rid of non-bitcoin networks which make it hard to run these tests
foreach my $network_id (Bitcoin::Crypto::Network->find(sub { shift->id !~ m{^bitcoin} })) {
	Bitcoin::Crypto::Network->get($network_id)->unregister;
}

my @cases = (
	[
		'one P2TR key only input with internal key and its derivation path',
		'cHNidP8BAFICAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAFgAUdo4e60z0IIZgM/gKzv8PlyB0SWkAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgAiAgNrdyptt02HU8mKgnlY3mx4qzMSEJ830+AwRIQkLs5z2Bh3Ky2nVAAAgAEAAIAAAACAAAAAAAAAAAAA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			my $input_derivation = $psbt->get_field('PSBT_IN_TAP_BIP32_DERIVATION', 0);
			is to_format [hex => $input_derivation->key->get_xonly_key],
				'fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232', 'input derivation key ok';

			my $bip32 = $input_derivation->value;
			is scalar @$bip32, 3, 'input bip32 data count ok';
			is [map { to_format [hex => $_] } @{$bip32->[0]}], [], 'input leaf hashes ok';
			is to_format [hex => $bip32->[1]], '772b2da7', 'input bip32 master key fingerprint ok';
			is $bip32->[2]->as_string, "m/86'/1'/0'/1/0", 'input bip32 path ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_TAP_INTERNAL_KEY', 0)->value->get_xonly_key],
				'fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232', 'input internal key ok';
		},
	],

	[
		'one P2TR key only input with internal key, its derivation path, and signature',
		'cHNidP8BAFICAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAFgAUdo4e60z0IIZgM/gKzv8PlyB0SWkAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1cBE0C7U+yRe62dkGrxuocYHEi4as5aritTYFpyXKdGJWMUdvxvW67a9PLuD0d/NvWPOXDVuCc7fkl7l68uPxJcl680IRb+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMhkAdystp1YAAIABAACAAAAAgAEAAAAAAAAAARcg/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIAIgIDa3cqbbdNh1PJioJ5WN5seKszEhCfN9PgMESEJC7Oc9gYdystp1QAAIABAACAAAAAgAAAAAAAAAAAAA==',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			is to_format [hex => $psbt->get_field('PSBT_IN_TAP_KEY_SIG', 0)->value],
				'bb53ec917bad9d906af1ba87181c48b86ace5aae2b53605a725ca74625631476fc6f5baedaf4f2ee0f477f36f58f3970d5b8273b7e497b97af2e3f125c97af34',
				'input signature ok';
		},
	],

	[
		'one P2TR key only output with internal key and its derivation path',
		'cHNidP8BAF4CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgABBSARJNp67JLM0GyVRWJkf0N7E4uVchqEvivyJ2u92rPmcSEHESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEZAHcrLadWAACAAQAAgAAAAIAAAAAABQAAAAA=',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			my $output_derivation = $psbt->get_field('PSBT_OUT_TAP_BIP32_DERIVATION', 0);
			is to_format [hex => $output_derivation->key->get_xonly_key],
				'1124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e671', 'output derivation key ok';

			my $bip32 = $output_derivation->value;
			is scalar @$bip32, 3, 'output bip32 data count ok';
			is [map { to_format [hex => $_] } @{$bip32->[0]}], [], 'output leaf hashes ok';
			is to_format [hex => $bip32->[1]], '772b2da7', 'output bip32 master key fingerprint ok';
			is $bip32->[2]->as_string, "m/86'/1'/0'/0/5", 'output bip32 path ok';

			is to_format [hex => $psbt->get_field('PSBT_OUT_TAP_INTERNAL_KEY', 0)->value->get_xonly_key],
				'1124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e671', 'output internal key ok';
		},
	],

	[
		'one P2TR script path only input with dummy internal key, scripts, derivation paths for keys in the scripts, and merkle root',
		'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgjICyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSrMBCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wJfG5v6l/3FP9XJEmZkIEOQG6YqhD1v35fZ4S8HQqabOIyBDILC/FvARtT6nvmFZJKp/J+XSmtIOoRVdhIZ2w7rRsqzAYhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDNlw4V9T/AyC+VD9Vg/6kZt2FyvgFzaKiZE68HT0ALCRFfLkkK98xFxPeFEfNgV85cWlxWMlop+0TfwgPzVuH4IyD6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqazAIRYssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20jkBzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwl3Ky2nVgAAgAEAAIACAACAAAAAAAAAAAAhFkMgsL8W8BG1Pqe+YVkkqn8n5dKa0g6hFV2EhnbDutGyOQERXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+HcrLadWAACAAQAAgAEAAIAAAAAAAAAAACEWUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAFAHxGHl0hFvoPejzvOx0MCmzn0m4XraCy5cktGe+tSLQYWcuKRRypOQFvfWIFnpSXoaSiZ1admHbaYBAa/zjjUpubk5zn+RrpcHcrLadWAACAAQAAgAMAAIAAAAAAAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARgg8DYuL3Wm9CClvePrIh2WrmcgzyX4GJDJWx13WstRXmUAAQUgESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEhBxEk2nrskszQbJVFYmR/Q3sTi5VyGoS+K/Ina73as+ZxGQB3Ky2nVgAAgAEAAIAAAACAAAAAAAUAAAAA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			my $merkle_root = $psbt->get_field('PSBT_IN_TAP_MERKLE_ROOT', 0)->value;
			is to_format [hex => $merkle_root], 'f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65',
				'merkle root ok';
			foreach my $script_field ($psbt->get_all_fields('PSBT_IN_TAP_LEAF_SCRIPT', 0)) {
				my $control_block = $script_field->key;
				my ($script, $leaf_version) = @{$script_field->value};
				my $tree = btc_script_tree->from_path(
					{leaf_version => $leaf_version, script => $script},
					$control_block->script_blocks
				);
				is to_format [hex => $tree->get_merkle_root], to_format [hex => $merkle_root], 'merkle root ok';

				my $input_derivation =
					$psbt->get_field('PSBT_IN_TAP_BIP32_DERIVATION', 0, $control_block->public_key->get_xonly_key);
				is to_format [hex => $input_derivation->value->[1]], '7c461e5d',
					'master key fingerprint ok';
			}
		},
	],

	[
		'one P2TR script path only output with dummy internal key, taproot tree, and script key derivation paths',
		'cHNidP8BAF4CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAIlEgCoy9yG3hzhwPnK6yLW33ztNoP+Qj4F0eQCqHk0HW9vUAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgABBSBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wAEGbwLAIiBzblcpAP4SUliaIUPI88efcaBBLSNTr3VelwHHgmlKAqwCwCIgYxxfO1gyuPvev7GXBM7rMjwh9A96JPQ9aO8MwmsSWWmsAcAiIET6pJoDON5IjI3//s37bzKfOAvVZu8gyN9tgT6rHEJzrCEHRPqkmgM43kiMjf/+zftvMp84C9Vm7yDI322BPqscQnM5AfBreYuSoQ7ZqdC7/Trxc6U7FhfaOkFZygCCFs2Fay4Odystp1YAAIABAACAAQAAgAAAAAADAAAAIQdQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wAUAfEYeXSEHYxxfO1gyuPvev7GXBM7rMjwh9A96JPQ9aO8MwmsSWWk5ARis5AmIl4Xg6nDO67jhyokqenjq7eDy4pbPQ1lhqPTKdystp1YAAIABAACAAgAAgAAAAAADAAAAIQdzblcpAP4SUliaIUPI88efcaBBLSNTr3VelwHHgmlKAjkBKaW0kVCQFi11mv0/4Pk/ozJgVtC0CIy5M8rngmy42Cx3Ky2nVgAAgAEAAIADAACAAAAAAAMAAAAA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			my $tree = $psbt->get_field('PSBT_OUT_TAP_TREE', 0)->value;
			my $structure = $tree->tree;

			is to_format [hex => $structure->[0][0]{hash}],
				'29a5b4915090162d759afd3fe0f93fa3326056d0b4088cb933cae7826cb8d82c', 'tree hash 1 ok';
			is to_format [hex => $structure->[0][1]{hash}],
				'18ace409889785e0ea70ceebb8e1ca892a7a78eaede0f2e296cf435961a8f4ca', 'tree hash 2 ok';
			is to_format [hex => $structure->[1]{hash}],
				'f06b798b92a10ed9a9d0bbfd3af173a53b1617da3a4159ca008216cd856b2e0e', 'tree hash 3 ok';

			is to_format [hex => $tree->get_merkle_root],
				'36a5d399284ffec625a7d9a81a2dd5f5e5049b7a7db013126f323aa3ce3f04ba', 'merkle root ok';
		},
	],

	[
		'one P2TR script path only input with dummy internal key, scripts, script key derivation paths, merkle root, and script path signatures',
		'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJBFCyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwlAv4GNl1fW/+tTi6BX+0wfxOD17xhudlvrVkeR4Cr1/T1eJVHU404z2G8na4LJnHmu0/A5Wgge/NLMLGXdfmk9eUEUQyCwvxbwEbU+p75hWSSqfyfl0prSDqEVXYSGdsO60bIRXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+EDh8atvq/omsjbyGDNxncHUKKt2jYD5H5mI2KvvR7+4Y7sfKlKfdowV8AzjTsKDzcB+iPhCi+KPbvZAQ8MpEYEaQRT6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqW99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwQOwfA3kgZGHIM0IoVCMyZwirAx8NpKJT7kWq+luMkgNNi2BUkPjNE+APmJmJuX4hX6o28S3uNpPS2szzeBwXV/ZiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgjICyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSrMBCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wJfG5v6l/3FP9XJEmZkIEOQG6YqhD1v35fZ4S8HQqabOIyBDILC/FvARtT6nvmFZJKp/J+XSmtIOoRVdhIZ2w7rRsqzAYhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDNlw4V9T/AyC+VD9Vg/6kZt2FyvgFzaKiZE68HT0ALCRFfLkkK98xFxPeFEfNgV85cWlxWMlop+0TfwgPzVuH4IyD6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqazAIRYssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20jkBzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwl3Ky2nVgAAgAEAAIACAACAAAAAAAAAAAAhFkMgsL8W8BG1Pqe+YVkkqn8n5dKa0g6hFV2EhnbDutGyOQERXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+HcrLadWAACAAQAAgAEAAIAAAAAAAAAAACEWUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAFAHxGHl0hFvoPejzvOx0MCmzn0m4XraCy5cktGe+tSLQYWcuKRRypOQFvfWIFnpSXoaSiZ1admHbaYBAa/zjjUpubk5zn+RrpcHcrLadWAACAAQAAgAMAAIAAAAAAAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARgg8DYuL3Wm9CClvePrIh2WrmcgzyX4GJDJWx13WstRXmUAAQUgESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEhBxEk2nrskszQbJVFYmR/Q3sTi5VyGoS+K/Ina73as+ZxGQB3Ky2nVgAAgAEAAIAAAACAAAAAAAUAAAAA',
		sub {
			my $psbt = shift;
			is $psbt->input_count, 1, 'input count ok';
			is $psbt->output_count, 1, 'output count ok';

			my @script_sigs = $psbt->get_all_fields('PSBT_IN_TAP_SCRIPT_SIG', 0);

			is to_format [hex => $script_sigs[0]->key->[0]->get_xonly_key],
				'2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2', 'first script sig pubkey ok';
			is to_format [hex => $script_sigs[0]->key->[1]],
				'cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09', 'first script leaf hash ok';
			is to_format [hex => $script_sigs[0]->value],
				'bf818d9757d6ffeb538ba057fb4c1fc4e0f5ef186e765beb564791e02af5fd3d5e2551d4e34e33d86f276b82c99c79aed3f0395a081efcd2cc2c65dd7e693d79',
				'first script signature ok';

			is to_format [hex => $script_sigs[1]->key->[0]->get_xonly_key],
				'4320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2', 'second script sig pubkey ok';
			is to_format [hex => $script_sigs[1]->key->[1]],
				'115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f8', 'second script leaf hash ok';
			is to_format [hex => $script_sigs[1]->value],
				'e1f1ab6fabfa26b236f21833719dc1d428ab768d80f91f9988d8abef47bfb863bb1f2a529f768c15f00ce34ec283cdc07e88f8428be28f6ef64043c32911811a',
				'second script signature ok';

			is to_format [hex => $script_sigs[2]->key->[0]->get_xonly_key],
				'fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9', 'third script sig pubkey ok';
			is to_format [hex => $script_sigs[2]->key->[1]],
				'6f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970', 'third script leaf hash ok';
			is to_format [hex => $script_sigs[2]->value],
				'ec1f0379206461c83342285423326708ab031f0da4a253ee45aafa5b8c92034d8b605490f8cd13e00f989989b97e215faa36f12dee3693d2daccf3781c1757f6',
				'third script signature ok';
		},
	],
);

foreach my $case (@cases) {
	my ($name, $base64, $checker) = @{$case};

	subtest $name => sub {
		my $psbt;
		ok lives {
			$psbt = btc_psbt->from_serialized([base64 => $base64]);
		}, 'deserialization ok';

		$checker->($psbt) if $checker;

		# try all serializers and deserializers
		my @fields = $psbt->list_fields;
		my $new_psbt = btc_psbt->new;
		foreach my $field (@fields) {
			my @field_objs = $psbt->get_all_fields(@$field);

			foreach my $field_obj (@field_objs) {
				my $new_field_obj = Bitcoin::Crypto::PSBT::Field->new(
					type => $field->[0],
					key => $field_obj->key,
					value => $field_obj->value,
				);
				$new_psbt->add_field($new_field_obj, $field->[1]);

				is to_format [hex => $new_field_obj->to_serialized],
					to_format [hex => $field_obj->to_serialized], 'serialized field ' . $field->[0]->name . ' ok';
			}
		}

		is to_format [base64 => $new_psbt->to_serialized], $base64, 'serialized psbt ok';
	};
}

done_testing;

