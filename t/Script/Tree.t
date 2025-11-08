use Test2::V0;
use Bitcoin::Crypto qw(btc_script_tree);
use Bitcoin::Crypto::Util qw(to_format);

# this example is a modified test case from BIP341
my $tree = btc_script_tree->new(
	tree => [
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
);

my $tree_prehashed = btc_script_tree->new(
	tree => [
		{hash => [hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d']},
		[
			{
				leaf_version => 192,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
			{hash => [hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7']},
		]
	]
);

my $tree_from_path = btc_script_tree->from_path(
	{
		leaf_version => 192,
		script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
	}, [
		[hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7'],
		[hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d'],
	]
);

subtest 'testing merkle_root' => sub {
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

subtest 'testing from_path with empty path' => sub {
	my $tree;
	ok lives {
		$tree = btc_script_tree->from_path(
			{
				leaf_version => 192,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
			[]
		);
	};
};

done_testing;

