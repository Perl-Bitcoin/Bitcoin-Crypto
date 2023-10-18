use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

btc_utxo->extract(
	[
		hex =>
			'01000000000101a250038cc5d95095d732b66cd085818c4747d76a978f5cf275b6e8351986eef50000000000ffffffff016daa0200000000001976a91420a16a3c6ae19789e3f8fd83186b925a0f4ea5e688ac02483045022100de84d1f0077ff5c6215898adecb48e390399415ef80382794abbce6e2602a9c602202d508c3d9bf358e83e425d07208f84505abb47dc6015bf73c2f88569c44917770121026ac933fdc659a7e5549bef5c900168c58cabd5dad0e5b889c9c1159b12d5977300000000'
	]
);

$tx->add_input(
	utxo => [[hex => '9fd09a5833ecc410eacc6a7e32af2313cbdbee16dd190029adb895b40e13852c'], 0],
);

$tx->add_output(
	locking_script => [P2WPKH => 'tb1q26jy9d4vkfqezh6hm7qp7txvk8nggkwv2y72x0'],
	value => 0,
);

$tx->outputs->[0]->set_value($tx->fee - 300);

btc_prv->from_wif('cQfP4Xsei1Vx5w6SUvbZ6h9WS9Rxf858bg2jH9VSt4hiNYGjgsLu')->sign_transaction($tx, signing_index => 0);

$tx->verify;
say $tx->dump;
say to_format [hex => $tx->to_serialized];

__END__

=head1 P2PKH transaction example

A legacy transaction spending one P2PKH inputs and produces a single P2WPKH
output. The transaction was generated without optional modules for deterministic signatures.

This code was used to produce testnet transaction:
L<https://mempool.space/testnet/tx/92d20051a04bd680a519d778484843a5d05d92973a5bb8efb6db00e0de8baedc>

