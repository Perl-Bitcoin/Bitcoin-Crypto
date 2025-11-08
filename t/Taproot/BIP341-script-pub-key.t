use Test2::V0;
use Bitcoin::Crypto qw(btc_pub btc_script_tree);
use Bitcoin::Crypto::Util qw(to_format lift_x);

# Data from:
# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#test-vectors

my @cases = (
	{
		expected => {
			bip350_address => 'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5',
			script_pub_key => '512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343'
		},
		given => {
			internal_pubkey => 'd6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d',
			script_tree => undef
		},
	},
	{
		expected => {
			bip350_address => 'bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586',
			script_path_control_blocks => [
				'c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27'
			],
			script_pub_key => '5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3'
		},
		given => {
			internal_pubkey => '187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27',
			script_tree => [
				{
					id => 0,
					leaf_version => 192,
					script => [hex => '20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac']
				}
			]
		},
	},
	{
		expected => {
			bip350_address => 'bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5',
			script_path_control_blocks => [
				'c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820'
			],
			script_pub_key => '5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e'
		},
		given => {
			internal_pubkey => '93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820',
			script_tree => [
				{
					id => 0,
					leaf_version => 192,
					script => [hex => '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac']
				}
			]
		},
	},
	{
		expected => {
			bip350_address => 'bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm',
			script_path_control_blocks => [
				'c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a',
				'faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7'
			],
			script_pub_key => '5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5'
		},
		given => {
			internal_pubkey => 'ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592',
			script_tree => [
				{
					id => 0,
					leaf_version => 192,
					script => [hex => '20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac']
				},
				{
					id => 1,
					leaf_version => 250,
					script => [hex => '06424950333431']
				}
			]
		},
	},
	{
		expected => {
			bip350_address => 'bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq',
			script_path_control_blocks => [
				'c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd82cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb',
				'c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd864512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89'
			],
			script_pub_key => '512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220'
		},
		given => {
			internal_pubkey => 'f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8',
			script_tree => [
				{
					id => 0,
					leaf_version => 192,
					script => [hex => '2044b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fdac']
				},
				{
					id => 1,
					leaf_version => 192,
					script => [hex => '07546170726f6f74']
				}
			]
		},
	},
	{
		expected => {
			bip350_address => 'bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e',
			script_path_control_blocks => [
				'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553',
				'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817',
				'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817'
			],
			script_pub_key => '512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605'
		},
		given => {
			internal_pubkey => 'e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f',
			script_tree => [
				{
					id => 0,
					leaf_version => 192,
					script => [hex => '2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac']
				},
				[
					{
						id => 1,
						leaf_version => 192,
						script => [hex => '202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac']
					},
					{
						id => 2,
						leaf_version => 192,
						script => [hex => '207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac']
					}
				]
			]
		},
	},
	{
		expected => {
			bip350_address => 'bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe',
			script_path_control_blocks => [
				'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91',
				'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d',
				'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d'
			],
			script_pub_key => '512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831'
		},
		given => {
			internal_pubkey => '55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d',
			script_tree => [
				{
					id => 0,
					leaf_version => 192,
					script => [hex => '2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac']
				},
				[
					{
						id => 1,
						leaf_version => 192,
						script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
					},
					{
						id => 2,
						leaf_version => 192,
						script => [hex => '20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac']
					}
				]
			]
		},
	}
);

foreach my $case_ind (0 .. $#cases) {
	subtest "should pass case index $case_ind" => sub {
		my $case = $cases[$case_ind];

		my $key = btc_pub->from_serialized(lift_x [hex => $case->{given}{internal_pubkey}]);
		my $tree;
		$tree = btc_script_tree->new(tree => $case->{given}{script_tree})
			if $case->{given}{script_tree};

		is $key->get_taproot_address($tree), $case->{expected}{bip350_address}, 'address ok';

		if ($tree) {
			foreach my $control_block_id (0 .. $#{$case->{expected}{script_path_control_blocks}}) {
				my $expected = $case->{expected}{script_path_control_blocks}[$control_block_id];
				my $got = $tree->get_control_block($control_block_id, $key);

				is to_format [hex => $got->to_serialized], $expected, "control block $control_block_id ok";
			}
		}
	};
}

done_testing;

