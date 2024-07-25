use Test2::V0;
use Bitcoin::Crypto qw(btc_transaction btc_script btc_utxo btc_block);
use Bitcoin::Crypto::Script::Runner;

my @cases = (
	[
		'CLTV with zero locktime',
		{
			transaction => {
				locktime => 0,
			},
			block => {
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(21333),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'height satisfied',
		{
			transaction => {
				locktime => 21333,
			},
			block => {
				height => 21333,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(21333),
		undef,
	],

	[
		'height unsatisfied - CLTV',
		{
			transaction => {
				locktime => 21333,
			},
			block => {
				height => 21333,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(21333 + 1),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'height unsatisfied - locktime',
		{
			transaction => {
				locktime => 21333,
			},
			block => {
				height => 21333 - 1,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(21333),
		'Bitcoin::Crypto::Exception::Transaction',
	],

	[
		'time satisfied',
		{
			transaction => {
				locktime => 1472653723,
			},
			block => {
				timestamp => 1472653723,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(1472653723),
		undef,
	],

	[
		'time unsatisfied - CLTV',
		{
			transaction => {
				locktime => 1472653723,
			},
			block => {
				timestamp => 1472653723,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(1472653723 + 1),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'time unsatisfied - locktime',
		{
			transaction => {
				locktime => 1472653723,
			},
			block => {
				timestamp => 1472653723 - 1,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(1472653723),
		'Bitcoin::Crypto::Exception::Transaction',
	],

	[
		'CLTV mixed 1',
		{
			transaction => {
				locktime => 1472653723,
			},
			block => {
				timestamp => 1472653723,
				height => 0,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(21333),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],

	[
		'CLTV mixed 2',
		{
			transaction => {
				locktime => 21333,
			},
			block => {
				height => 21333,
			}
		},
		Bitcoin::Crypto::Script::Runner->from_int(1472653723),
		'Bitcoin::Crypto::Exception::TransactionScript',
	],
);

btc_utxo->new(
	txid => [hex => '10c3227c159290319a305019dae6a4a0c0336e3dc25e220230ac8b2900c8fc4f'],
	output_index => 0,
	output => {
		locking_script => btc_script->new
			->add('OP_CHECKLOCKTIMEVERIFY')
			->add('OP_TRUE'),
		value => 1000,
	},
)->register;

foreach my $case (@cases) {
	my ($hash_name, $args, $locktime, $exception) = @$case;

	subtest "testing $hash_name" => sub {
		my $transaction = btc_transaction->new($args->{transaction});
		$transaction->add_input(
			utxo => [[hex => '10c3227c159290319a305019dae6a4a0c0336e3dc25e220230ac8b2900c8fc4f'], 0],
			signature_script => btc_script->new->push($locktime),
			sequence_no => 0xfffffffe,
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

