use Test2::V0;
use Bitcoin::Crypto qw(btc_transaction btc_utxo);

my $utxo = btc_utxo->new(
	txid => "\x22" x 32,
	output_index => 1,
	output => {
		locking_script => [address => 'bc1q6xlft774gf26n6gpjhyqrnepuua6fla5zzq5lm'],
		value => 1000,
	}
);

my $tx = btc_transaction->new;

$tx->add_input(
	utxo => $utxo,
	signature_script => '00',
);

$tx->add_output(
	locking_script => [address => 'bc1q2su9hld0xz03fh886utu8jrpk34f2n2598fqzu'],
	value => 900,
);

my $dump = $tx->dump;
note $dump;

my $txid = unpack 'H*', $tx->txid;
like $dump, qr{Transaction $txid}, 'has transaction id';
like $dump, qr{fee: 100 sat}, 'has fee';

like $dump, qr{P2WPKH Input from bc1q6xlft774gf26n6gpjhyqrnepuua6fla5zzq5lm}, 'has input';
like $dump, qr{spending output #1 from 2222222222222222222222222222222222222222222222222222222222222222},
	'has utxo location';
like $dump, qr{locking script: P2WPKH script, 2 ops:}, 'has dumped locking script';
like $dump, qr{signature script: Custom script \(with errors\), 1 ops:}, 'has dumped signature script';

like $dump, qr{P2WPKH Output to bc1q2su9hld0xz03fh886utu8jrpk34f2n2598fqzu}, 'has output';

done_testing;

