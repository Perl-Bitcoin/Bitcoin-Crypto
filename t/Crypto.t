use Test2::V0;
use Bitcoin::Crypto qw(:all);

my @cases = (
	[
		'Bitcoin::Crypto::Key::ExtPrivate',
		\&btc_extprv,
	],
	[
		'Bitcoin::Crypto::Key::Private',
		\&btc_prv,
	],
	[
		'Bitcoin::Crypto::Key::ExtPublic',
		\&btc_extpub,
	],
	[
		'Bitcoin::Crypto::Key::Public',
		\&btc_pub,
	],
	[
		'Bitcoin::Crypto::Script',
		\&btc_script,
	],
	[
		'Bitcoin::Crypto::Block',
		\&btc_block,
	],
	[
		'Bitcoin::Crypto::Transaction',
		\&btc_transaction,
	],
	[
		'Bitcoin::Crypto::Transaction::UTXO',
		\&btc_utxo,
	],
	[
		'Bitcoin::Crypto::PSBT',
		\&btc_psbt,
	],
);

foreach my $case (@cases) {
	my ($expected_package, $func) = @$case;

	subtest "testing $expected_package" => sub {
		my $package = $func->();
		is $package, $expected_package;
	}
}

done_testing;

