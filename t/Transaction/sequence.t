use Test2::V0;
use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_block btc_script);
use Bitcoin::Crypto::Script::Runner;

sub create_sequence
{
	my ($enabled, $time_based, $value) = @_;
	$value //= 0;

	my $out = 0;
	$out |= 1 << 31
		unless $enabled;

	$out |= 1 << 22
		if $time_based;

	$value = int($value / 512)
		if $time_based;

	return $out | $value;
}

my @cases = (
	[
		'sequence disabled in transaction version 1',
		{
			transaction => {
				version => 1,
			},
			input_sequence => create_sequence(1, 0, 200),
			block => {
				height => 21333,
			},
			utxo_block => {
				height => 21333 - 1,
			}
		},

		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(0, 0, 200)),
		undef,
	],

	[
		'CSV error in transaction version 1',
		{
			transaction => {
				version => 1,
			},
			input_sequence => create_sequence(1, 0, 200),
			block => {
				height => 21333,
			},
			utxo_block => {
				height => 21333 - 1,
			}
		},

		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 0, 200)),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'height satisfied',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 0, 200),
			block => {
				height => 21333,
			},
			utxo_block => {
				height => 21333 - 200,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 0, 200)),
		undef,
	],

	[
		'height unsatisfied - sequence',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 0, 200),
			block => {
				height => 21333,
			},
			utxo_block => {
				height => 21333 - 200 + 1,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 0, 200)),
		'Bitcoin::Crypto::Exception::Transaction',
	],

	[
		'height unsatisfied - CSV',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 0, 200),
			block => {
				height => 21333,
			},
			utxo_block => {
				height => 21333 - 200,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 0, 200 + 1)),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'time satisfied',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 1, 51200),
			block => {
				timestamp => 1472653723,
				height => 1,
			},
			utxo_block => {
				timestamp => 1472653723 - 51200,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 1, 51200)),
		undef,
	],

	[
		'time unsatisfied - sequence',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 1, 51200),
			block => {
				timestamp => 1472653723,
				height => 1,
			},
			utxo_block => {
				timestamp => 1472653723 - 51200 + 1,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 1, 51200)),
		'Bitcoin::Crypto::Exception::Transaction',
	],

	[
		'time unsatisfied - CSV',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 1, 51200),
			block => {
				timestamp => 1472653723,
				height => 1,
			},
			utxo_block => {
				timestamp => 1472653723 - 51200,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 1, 51200 + 512)),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'CSV mixed 1',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 1, 51200),
			block => {
				timestamp => 1472653723,
				height => 1,
			},
			utxo_block => {
				timestamp => 1472653723 - 51200,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 0, 200)),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'CSV mixed 2',
		{
			transaction => {
				version => 2,
			},
			input_sequence => create_sequence(1, 0, 200),
			block => {
				height => 21333,
			},
			utxo_block => {
				height => 21333 - 200,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(create_sequence(1, 1, 51200)),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],
);

foreach my $case (@cases) {
	my ($hash_name, $args, $sequence, $exception) = @$case;

	btc_utxo->new(
		txid => [hex => '10c3227c159290319a305019dae6a4a0c0336e3dc25e220230ac8b2900c8fc4f'],
		block => btc_block->new($args->{utxo_block}),
		output_index => 0,
		output => {
			locking_script => btc_script->new
				->add('OP_CHECKSEQUENCEVERIFY')
				->add('OP_TRUE'),
			value => 1000,
		},
	)->register;

	subtest "testing $hash_name" => sub {
		my $transaction = btc_transaction->new($args->{transaction});
		$transaction->add_input(
			utxo => [[hex => '10c3227c159290319a305019dae6a4a0c0336e3dc25e220230ac8b2900c8fc4f'], 0],
			signature_script => btc_script->new->push($sequence),
			sequence_no => $args->{input_sequence},
		);

		my $ex = dies {
			$transaction->verify(block => btc_block->new($args->{block}));
		};

		is !!$ex, !!$exception, 'exception ok';

		if ($exception) {
			isa_ok $ex, $exception;
		}
	};
}

done_testing;

