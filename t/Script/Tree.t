use Test2::V0;
use Bitcoin::Crypto qw(btc_script_tree);
use Bitcoin::Crypto::Constants qw(:script);
use Bitcoin::Crypto::Util qw(from_format to_format);

subtest 'should calculate tree root' => sub {

	# this example is a modified test case from BIP341
	my $tree = btc_script_tree->new(
		tree => [
			{
				id => 'test1',
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => [hex => '2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac']
			},
			[
				{
					id => 'test2',
					leaf_version => TAPSCRIPT_LEAF_VERSION,
					script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
				},
				{
					id => 'test3',
					leaf_version => TAPSCRIPT_LEAF_VERSION,
					script => [hex => '20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac']
				}
			]
		]
	);

	my $tree_prehashed = btc_script_tree->new(
		tree => [
			{hash => [hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d']},
			[
				{
					leaf_version => TAPSCRIPT_LEAF_VERSION,
					script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
				},
				{hash => [hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7']},
			]
		]
	);

	my $tree_from_path = btc_script_tree->from_path(
		{
			leaf_version => TAPSCRIPT_LEAF_VERSION,
			script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
		}, [
			[hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7'],
			[hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d'],
		]
	);
	is(
		to_format [hex => $tree->get_merkle_root],
		'2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def',
		'merkle root ok'
	);

	is(
		to_format [hex => $tree_prehashed->get_merkle_root],
		'2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def',
		'prehashed merkle root ok'
	);

	is(
		to_format [hex => $tree_from_path->get_merkle_root],
		'2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def',
		'path merkle root ok'
	);
};

subtest 'tree merkle root should be equal to the hash of the single tree element' => sub {
	my $root = '2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def';
	my $tree_root_only = btc_script_tree->new(tree => [{hash => [hex => $root]}]);

	is(
		to_format [hex => $tree_root_only->get_merkle_root],
		$root,
		'precalculated merkle root ok'
	);
};

subtest 'should create a tree using from_path with empty path' => sub {
	ok lives {
		btc_script_tree->from_path(
			{
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
			[]
		);
	};
};

subtest 'should handle tree leaves' => sub {
	my $tree = btc_script_tree->new(
		tree => [
			{
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => [hex => '2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac']
			},
			{
				id => 'named',
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
		]
	);

	is to_format [
		hex => $tree->get_leaf([hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d'])->hash
		],
		'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d', 'hash of the unnamed element ok';

	is to_format [hex => $tree->get_leaf('named')->hash],
		'737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711', 'hash of the named element ok';

	my $leaves = $tree->get_leaves;
	is scalar @$leaves, 2, 'leaves count ok';
	is to_format [hex => $leaves->[0]->hash],
		'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d', 'first leaf ok';
	is to_format [hex => $leaves->[1]->hash],
		'737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711', 'second leaf ok';
};

subtest 'should return tree paths' => sub {

	# random blockchain addresses as scripts - we don't need the scripts to
	# actually be spendable for this test
	my $tree = btc_script_tree->new(
		tree => [
			{
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => [address => '3KWNverZRyoGfaAMPmZMeUacJPjxQaQ1V2'],
			},
			[
				{
					leaf_version => TAPSCRIPT_LEAF_VERSION,
					script => [address => '39UmMHarsXD9gmMTMCVhr2zM5RRVfcUd5e'],
				},
				{
					id => '3rd',    # hex: 337264
					leaf_version => TAPSCRIPT_LEAF_VERSION,
					script => [address => '3MwAixsvN1gDsXcqu9D9ZdeE4DkiDrHb47'],
				}
			]
		],
	);

	my $paths = $tree->get_tree_paths;
	is [sort map { to_format [hex => $_] } keys %$paths],
		[
			'337264',
			'8247536dbfa720a16aedb485b193407e00b1fa056d694e637589adbc48826b26',
			'8f0befb0caab67336b9ec250ebf3b8fea4c966e68b45d7a8d321570cf87519cf',
		],
		'tree keys ok';

	my $id;

	$id = '3rd';
	is [map { to_format [hex => $_] } @{$paths->{$id}}], [
		'8f0befb0caab67336b9ec250ebf3b8fea4c966e68b45d7a8d321570cf87519cf',
		'8247536dbfa720a16aedb485b193407e00b1fa056d694e637589adbc48826b26',
		],
		'paths for leaf 3rd ok';

	$id = from_format [hex => '8f0befb0caab67336b9ec250ebf3b8fea4c966e68b45d7a8d321570cf87519cf'];
	is [map { to_format [hex => $_] } @{$paths->{$id}}], [
		'bd576efc9e01b6f6a8eb537837e74e4b8d2b5c2aa1e11f01e4fdf27db71029e0',
		'8247536dbfa720a16aedb485b193407e00b1fa056d694e637589adbc48826b26',
		],
		'paths leaf #8f0be ok';

	$id = from_format [hex => '8247536dbfa720a16aedb485b193407e00b1fa056d694e637589adbc48826b26'];
	is [map { to_format [hex => $_] } @{$paths->{$id}}], [
		'95b40f13741c20dc695ca47e71c8207668617a819413d7e0f63ab3b0b43851d5',
		],
		'paths for leaf #82475 ok';
};

done_testing;

