use v5.10;
use strict;
use warnings;
use Test::More;

use Bitcoin::Crypto qw(btc_block);

my $start_height = 152643;
my $start_time = 1436091912;
my $interval = 600;

my $top = btc_block->new(
	timestamp => $start_time,
	height => $start_height,
);

sub add_blocks
{
	my ($count) = @_;

	for (1 .. $count) {
		$top = btc_block->new(
			timestamp => $top->timestamp + $interval,
			height => $top->height + 1,
			previous => $top,
		);
	}
}

subtest 'should calculate partial median_time_past' => sub {
	add_blocks(5);

	# all we have now is 6 blocks (1 + 5)
	# median should be from block index 3:
	# 0 1 2 (3) 4 top
	my $expected = $top->timestamp - 2 * $interval;
	is $top->median_time_past, $expected;
};

subtest 'should calculate full median_time_past' => sub {
	add_blocks(15);

	# we have full 11 blocks
	# median should be from block index 5:
	# 0 1 2 3 4 (5) 6 7 8 9 top
	my $expected = $top->timestamp - 5 * $interval;
	is $top->median_time_past, $expected;
};

done_testing;

