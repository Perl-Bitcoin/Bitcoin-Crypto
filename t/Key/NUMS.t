use Test2::V0;
use Bitcoin::Crypto::Key::NUMS;
use Bitcoin::Crypto::Util qw(to_format);

subtest 'should generate random NUMS points' => sub {
	my $nums = Bitcoin::Crypto::Key::NUMS->new();
	my $obj = $nums->get_public_key;

	isa_ok $obj, 'Bitcoin::Crypto::Key::Public';
};

subtest 'should reconstruct NUMS points' => sub {
	my $nums = Bitcoin::Crypto::Key::NUMS->new(tweak => [hex => '01' x 32]);
	my $obj = $nums->get_public_key;

	# NOTE: this value is not confirmed to be correct according to other NUMS
	# generators (if any exist), but it is using the algorithm that is
	# returning unspendable points
	is to_format [hex => $obj->to_serialized],
		'03ace1b93263794ecc2cd18b5352406aff1913eb3ce503a7d2f2c13ec41cb2500f', 'generated NUMS point ok';

	my $obj2 = $nums->get_public_key;

	ok $obj->to_serialized eq $obj2->to_serialized, 'NUMS point deterministic generation ok';
};

done_testing;

