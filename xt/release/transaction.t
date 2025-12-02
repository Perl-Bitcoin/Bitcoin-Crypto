# HARNESS-DURATION-LONG
use Test2::V0;

use Bitcoin::Crypto qw(btc_transaction btc_utxo);
use Bitcoin::Crypto::Constants qw(:coin);

use lib 't/lib';
use BitcoinCoreTest;

test_tx('tx_valid', !!1);
test_tx('tx_invalid', !!0);

done_testing;

sub test_tx
{
	my ($case_name, $expected_result) = @_;

	my $data = get_file_data($case_name);
	my @actual_data;
	my @comments;

	foreach my $item (@$data) {
		if (@$item > 1) {
			push @actual_data, {
				data => $item,
				comments => [@comments],
			};

			@comments = ();
		}
		else {
			push @comments, $item->[0];
		}
	}

	foreach my $case_ind (0 .. $#actual_data)
	{
		my $case = $actual_data[$case_ind];

		subtest "should pass $case_name index $case_ind" => sub {
			my ($prevouts, $serialized_tx, $flags) = @{$case->{data}};

			foreach my $comment (@{$case->{comments}}) {
				note $comment;
			}

			my $tx = btc_transaction->from_serialized([hex => $serialized_tx]);

			foreach my $prevout_index (0 .. $#$prevouts) {
				my ($txid, $index, $script, $amount) = @{$prevouts->[$prevout_index]};

				# core test uses prevouts with negative indexes for coinbase -
				# nasty hack on their part!
				next if $index < 0;

				my $utxo = btc_utxo->new(
					txid => [hex => $txid],
					output_index => $index,
					output => {
						locking_script => script_from_readable($script),
						value => $amount // MAX_MONEY,
					},
				)->register;
			}

			$flags = get_flags $flags, $expected_result;
			if ($expected_result) {
				ok lives { $tx->verify(flags => $flags) }, 'verification ok';
			}
			else {
				my $ex = dies { $tx->verify(flags => $flags) };
				is $ex,
					in_set(
						check_isa('Bitcoin::Crypto::Exception::Transaction'),
						check_isa('Bitcoin::Crypto::Exception::UTXO')
					),
					'exception class ok';
			}
		};
	}
}

