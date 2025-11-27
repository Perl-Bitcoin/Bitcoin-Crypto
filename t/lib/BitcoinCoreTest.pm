package BitcoinCoreTest;

use v5.10;
use strict;
use warnings;

use Test2::V0;
use JSON::MaybeXS qw(decode_json);
use Try::Tiny;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_script btc_tapscript btc_script_tree);
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Transaction::Flags;
use Bitcoin::Crypto::Key::NUMS;

# returns consensus flags object. With reverse arguments, returns consensus
# without given flags
sub get_flags
{
	my ($string, $reverse) = @_;
	$reverse //= !!0;

	state $core_to_perl = {
		P2SH => 'p2sh',
		DERSIG => 'der_signatures',
		CHECKLOCKTIMEVERIFY => 'checklocktimeverify',
		CHECKSEQUENCEVERIFY => 'checksequenceverify',
		NULLDUMMY => 'nulldummy',
		WITNESS => 'segwit',
		TAPROOT => 'taproot',

		CONST_SCRIPTCODE => 'const_script',
		LOW_S => 'low_s_signatures',
		STRICTENC => 'strict_encoding',
		MINIMALIF => 'minimalif',
		NULLFAIL => 'nullfail',
		SIGPUSHONLY => 'signature_pushes_only',
		MINIMALDATA => 'minimaldata',
		CLEANSTACK => 'cleanstack',
		DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM => 'known_witness',
		WITNESS_PUBKEYTYPE => 'compressed_pubkeys',
		DISCOURAGE_UPGRADABLE_NOPS => 'illegal_upgradeable_nops',
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
	my ($readable_string, $tapscript) = @_;
	$tapscript //= !!0;

	my $script = $tapscript ? btc_tapscript->new : btc_script->new;
	my @parts = grep { length } split /\s+/, $readable_string;

	foreach my $part (@parts) {
		if ($part =~ m/^-?[0-9]+$/) {
			$script->push_number($part);
		}
		elsif ($part =~ m/^0x([0-9a-f]+)$/i) {
			$script->add_raw([hex => $1]);
		}
		elsif ($part =~ m/^'([^']*)'$/) {
			$script->push_bytes($1 // '');
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

sub test_script
{
	my ($case_name) = @_;

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

	my $source_tx = btc_transaction->new;
	$source_tx->add_input(
		utxo => Bitcoin::Crypto::Constants::null_utxo,
		signature_script => btc_script->from_serialized("\x00\x00"),
	);

	my $script_runner = Bitcoin::Crypto::Script::Runner->new;
	my $tapkey_internal = Bitcoin::Crypto::Key::NUMS->new(tweak => "\x00" x 32)->get_public_key;
	foreach my $case_ind (0 .. $#actual_data)
	{
		my $case = $actual_data[$case_ind];

		subtest "should pass $case_name index $case_ind" => sub {
			my @witness;
			@witness = @{shift @{$case->{data}}}
				if ref $case->{data}[0] eq 'ARRAY';

			my ($signature_raw, $script_raw, $flags, $error, @comments) = @{$case->{data}};
			$flags = get_flags $flags;
			my $taproot = $flags->taproot;
			my $tapscript;

			foreach my $comment (@{$case->{comments}}, @comments) {
				note $comment;
			}

			note "Script: $script_raw";

			my $amount = 0;
			if (@witness) {
				$amount = int(pop(@witness) * Bitcoin::Crypto::Constants::units_per_coin);

				if ($taproot) {
					my $block = pop @witness;
					die 'bad taproot case (no control block)' unless $block eq '#CONTROLBLOCK#';

					$tapscript = pop @witness;
					die 'bad taproot case (no script)' unless $tapscript =~ s/^#SCRIPT#//;
					$tapscript = script_from_readable($tapscript, -tapscript);
				}

				@witness = map { pack 'H*', $_ } @witness;
			}

			if ($taproot) {
				die 'bad taproot case (no script)' unless $tapscript;

				my $tree = btc_script_tree->new(
					tree => [
						{
							id => 0,
							leaf_version => Bitcoin::Crypto::Constants::tapscript_leaf_version,
							script => $tapscript,
						}
					]
				);

				push @witness, $tapscript->to_serialized;
				push @witness, $tree->get_control_block(0, $tapkey_internal)->to_serialized;
				my $tapkey_output = $tapkey_internal->get_taproot_output_key($tree->get_merkle_root)->get_xonly_key;
				my $tapkey_output_hex = unpack 'H*', $tapkey_output;
				$script_raw =~ s/#TAPROOTOUTPUT#/0x$tapkey_output_hex/;
			}

			my $tx = btc_transaction->new;

			try {
				@{$source_tx->outputs} = ();
				$source_tx->add_output(
					locking_script => script_from_readable($script_raw),
					value => $amount,
				);

				$tx->add_input(
					utxo => btc_utxo->new(
						txid => $source_tx->get_hash,
						output_index => 0,
						output => $source_tx->outputs->[0],
					),
					signature_script => script_from_readable($signature_raw),
					witness => \@witness,
				);
			}
			catch {
				my $e = $_;

				if (blessed $e && $e->isa('Bitcoin::Crypto::Exception::ScriptOpcode')) {
					my $msg = $e->message;

					skip_all "$msg" if $msg =~ /unknown opcode/;
				}
				die $e;
			};

			$tx->add_output(
				locking_script => '',
				value => $amount,
			);

			$script_runner->set_transaction($tx);
			$script_runner->set_flags($flags);
			if (!$error || $error eq 'OK') {
				ok lives { $tx->verify_script(0, $script_runner) }, 'verification ok';
			}
			else {
				note "Error comment: $error";
				my $ex = dies { $tx->verify_script(0, $script_runner) };
				isa_ok $ex, 'Bitcoin::Crypto::Exception::TransactionScript';
			}
		};
	}
}

1;

