package BitcoinCoreTest;

use v5.10;
use strict;
use warnings;

use Test2::V0;
use JSON::MaybeXS qw(decode_json);

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_script);
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Transaction::Flags;

# returns consensus flags object. With reverse arguments, returns consensus
# without given flags
sub get_flags
{
	my ($string, $reverse) = @_;
	$reverse //= !!0;

	state $core_to_perl = {
		P2SH => 'p2sh',
		DERSIG => 'strict_signatures',
		CHECKLOCKTIMEVERIFY => 'checklocktimeverify',
		CHECKSEQUENCEVERIFY => 'checksequenceverify',
		NULLDUMMY => 'nulldummy',
		WITNESS => 'segwit',
		TAPROOT => 'taproot',

		CONST_SCRIPTCODE => 'const_script',
		LOW_S => 'strict_signatures',
		STRICTENC => 'strict_signatures',
		MINIMALIF => 'minimalif',
		NULLFAIL => 'nullfail',
		SIGPUSHONLY => 'signature_pushes_only',
		MINIMALDATA => 'minimaldata',
		CLEANSTACK => 'cleanstack',
		DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM => 'known_witness',
	};

	my %flags = map { $core_to_perl->{$_} => !$reverse }
		grep { defined $core_to_perl->{$_} }
		split /,/, $string;

	my $method = $reverse ? 'new_full' : 'new_empty';
	return Bitcoin::Crypto::Transaction::Flags->$method(%flags);
}

sub get_file_data
{
	my ($case_name) = @_;

	local $/;

	my $file_location = $ENV{RELEASE_TESTS_DATA}
		or die 'no RELEASE_TESTS_DATA environmental variable was specified';

	my $file = "$file_location/$case_name.json";
	open my $fh, '<', $file
		or die "$case_name test requires file $file";

	return decode_json(readline $fh);
}

sub script_from_readable
{
	my ($readable_string) = @_;

	my $script = btc_script->new;
	my @parts = split /\s+/, $readable_string;

	foreach my $part (@parts) {
		if ($part =~ m/^-?[0-9]+$/) {
			$script->push_number($part);
		}
		elsif ($part =~ m/^0x([0-9a-f]+)$/i) {
			$script->add_raw([hex => $1]);
		}
		else {
			$part =~ s/^OP_//;
			$script->add("OP_$part");
		}
	}

	return $script;
}

sub test_validation
{
	my ($case_name) = @_;

	my $data = get_file_data($case_name);

	my $script_runner = Bitcoin::Crypto::Script::Runner->new;
	foreach my $case_ind (0 .. $#$data)
	{
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
			foreach my $comment (@{$case->{comments}}) {
				note $comment;
			}

			my ($prevouts, $serialized_tx, $flags) = @{$case->{data}};
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
						value => $amount // Bitcoin::Crypto::Constants::max_money,
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

1;

