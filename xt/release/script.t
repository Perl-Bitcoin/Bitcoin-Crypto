# HARNESS-DURATION-LONG
use Test2::V0;
use Try::Tiny;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_script btc_script_tree);
use Bitcoin::Crypto::Key::NUMS;
use Bitcoin::Crypto::Script::Runner;

use lib 't/lib';
use BitcoinCoreTest;

my $case_name = 'script_tests';

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

done_testing;

