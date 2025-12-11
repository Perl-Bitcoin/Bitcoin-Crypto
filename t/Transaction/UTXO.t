use Test2::V0;
use Bitcoin::Crypto qw(btc_utxo btc_script);

subtest 'utxo count should be zero at start' => sub {
	is btc_utxo->registered_count, 0, 'count ok';
	is btc_utxo->unload, [], 'unload ok';
};

my @utxos;
for (1 .. 10) {
	push @utxos, btc_utxo->new(
		txid => chr() x 32,
		output_index => 0,
		output => {
			locking_script => btc_script->new->push(chr),
			value => 1500,
		},
	)->register;
}

subtest 'utxo count should grow and shrink when registering utxos' => sub {
	is btc_utxo->registered_count, 10, 'count ok';

	my $first = shift @utxos;
	$first->unregister;
	is btc_utxo->registered_count, 9, 'count after modification ok';
};

subtest 'should unload utxos' => sub {
	my @unloaded = @{btc_utxo->unload};
	@unloaded = sort { $a->txid cmp $b->txid } @unloaded;

	# @utxos were already created as sorted
	is \@unloaded, \@utxos, 'unloaded utxos ok';
};

subtest 'should not register nulldata utxos' => sub {
	btc_utxo->new(
		txid => "\x22" x 32,
		output_index => 0,
		output => {
			locking_script => [NULLDATA => 'test'],
			value => 1500,
		},
	)->register;

	is btc_utxo->registered_count, 0, 'NULLDATA was not registered ok';
};

done_testing;

