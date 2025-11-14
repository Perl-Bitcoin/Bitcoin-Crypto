package BitcoinCoreTest;

use v5.10;
use strict;
use warnings;

use Test2::V0;
use JSON::MaybeXS qw(decode_json);

use Bitcoin::Crypto qw(btc_transaction btc_utxo);
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Transaction::Flags;

sub get_flags
{
	my ($string) = @_;

	state $core_to_perl = {
		P2SH => 'p2sh',
		DERSIG => 'strict_signatures',
		CHECKLOCKTIMEVERIFY => 'checklocktimeverify',
		CHECKSEQUENCEVERIFY => 'checksequenceverify',
		NULLDUMMY => 'nulldummy',
		WITNESS => 'segwit',
		TAPROOT => 'taproot',
	};

	my %flags = map { $core_to_perl->{$_} => !!1 } split /,/, $string;

	return Bitcoin::Crypto::Transaction::Flags->new_empty(%flags);
}

sub test_validation
{
	my ($case_name, $single_case_ind) = @_;

	my $data = do {
		local $/;

		my $file_location = $ENV{RELEASE_TESTS_DATA} // 'xt/data';
		my $file = "$file_location/$case_name.json";
		open my $fh, '<', $file
			or skip_all "$case_name test requires file $file";

		decode_json(readline $fh);
	};

	my $script_runner = Bitcoin::Crypto::Script::Runner->new;
	foreach my $case_ind (0 .. $#$data)
	{
		next if defined $single_case_ind && $single_case_ind != $case_ind;
		my $case = $data->[$case_ind];

		subtest "should pass $case_name index $case_ind ($case->{comment})" => sub {
			my $tx = btc_transaction->from_serialized([hex => $case->{tx}]);

			my @last_outputs =
				map { Bitcoin::Crypto::Transaction::Output->from_serialized([hex => $_]) } @{$case->{prevouts}};
			foreach my $input (@{$tx->inputs}) {
				btc_utxo->new(
					txid => $input->utxo_location->[0],
					output_index => $input->utxo_location->[1],
					output => shift @last_outputs,
				)->register;
			}

			$script_runner->set_transaction($tx);
			$script_runner->set_flags(get_flags $case->{flags});
			my $index = $case->{index};
			my $input = $tx->inputs->[$index];

			foreach my $sub_case ([!!1, $case->{success}], [!!0, $case->{failure}]) {
				my ($success, $sub_case_data) = @$sub_case;
				next unless $sub_case_data;

				$input->set_signature_script([hex => $sub_case_data->{scriptSig}]);
				$input->set_witness([map { [hex => $_] } @{$sub_case_data->{witness}}]);

				if ($success) {
					ok lives { $tx->verify_script($index, $script_runner) }, 'success case ok';
				}
				else {
					my $ex = dies { $tx->verify_script($index, $script_runner) };
					isa_ok $ex, 'Bitcoin::Crypto::Exception::Transaction';
				}
			}
		};
	}
}

1;

