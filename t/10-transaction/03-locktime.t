use v5.10;
use strict;
use warnings;
use Test::More;
use Try::Tiny;

use Bitcoin::Crypto qw(btc_transaction btc_script);
use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Script::Runner;

my @cases = (
	[
		'locktime - zero',
		{locktime => 0},
		'5553',
		'Bitcoin::Crypto::Exception::TransactionInvalid',
	],
	[
		'locktime - satisfied (height)',
		{locktime => 21333},
		'5553',
		undef,
	],
	[
		'locktime - unsatisfied (height)',
		{locktime => 21332},
		'5553',
		'Bitcoin::Crypto::Exception::TransactionInvalid',
	],
	[
		'locktime - satisfied (time)',
		{locktime => 1472653723},
		'9be9c657',
		undef,
	],
	[
		'locktime - unsatisfied (time)',
		{locktime => 1472653722},
		'9be9c657',
		'Bitcoin::Crypto::Exception::TransactionInvalid',
	],
	[
		'locktime - unsatisfied (mixed 1)',
		{locktime => 1472653722},
		'5553',
		'Bitcoin::Crypto::Exception::TransactionInvalid',
	],
	[
		'locktime - unsatisfied (mixed 2)',
		{locktime => 21333},
		'9be9c657',
		'Bitcoin::Crypto::Exception::TransactionInvalid',
	],
);

Bitcoin::Crypto::Transaction::UTXO->new(
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
		my $transaction = btc_transaction->new($args);
		$transaction->add_input(
			utxo => [[hex => '10c3227c159290319a305019dae6a4a0c0336e3dc25e220230ac8b2900c8fc4f'], 0],
			signature_script => btc_script->new->push([hex => $locktime]),
			sequence_no => 0xfffffffe,
		);

		try {
			$transaction->verify;
			ok !$exception, 'exception ok';
		}
		catch {
			my $ex = $_;

			if ($exception) {
				isa_ok $ex, $exception;
			}
			else {
				note "died: $ex";
				fail "should've lived";
			}
		};
	};
}

done_testing;

