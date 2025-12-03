use v5.14;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

# this is the data of the transaction which created the output we want to spend
btc_utxo->extract(
	[
		hex =>
			'020000000001016988bad79cb141833a1481f619b11df8a83f69d06aa9019998ff52a12851a47a0200000000ffffffff0320a1070000000000225120f24502b7269e0aabccd908073982d0934e7ffb133f636352c8215970c8e00bfa0000000000000000196a17657465726e697479626974732e636f6d2f666175636574b08cb17717000000160014caf239ac9404a206852ced662305cab264e607a2024830450221008fa9b0508c11f95741adfabda2fc1f42f3e82bcdd28148f7605c29be71c9d72202203e0dc7b6763dd52fcb046221f000b67353b9d4c183e3332d748d6e694f7cc9af0121028f214ef5d4bc7faf117e266c0de34ba00338b0a906a717a27fc72b883b29b53300000000'
	]
);

# input must point to the transaction output above - transaction ID and output number
$tx->add_input(
	utxo => [[hex => '6ec2a8e05bb03f38834ad934ae007c7019e95abb7e2580e7c9cf3a9d98712e63'], 0],
);

# send all the coins to this address. The value will be adjusted to total minus fee
$tx->add_output(
	locking_script => [address => 'tb1ptsn34u3dvsuu77ktvtxaxl8de7m89dglke4a5zs6xs5ef39yyrkqtsv56z'],
	value => 0,
);

# calculate fee and set the value of first output. Unsigned tx virtual size is
# used, so the real fee rate will be approx two times smaller
my $wanted_fee_rate = 2;
$tx->outputs->[0]->set_value($tx->fee - int($tx->virtual_size * $wanted_fee_rate));

# sign all inputs with the corresponding private keys
btc_prv->from_wif('cR7NsFVFcYpm6eZg6LAXGtfh3GfLMmV48R9qe34oJSKW5DHfKjv2')->sign_transaction($tx, signing_index => 0);

# verify the correctness of the transaction. Throws an exception on failure
$tx->verify;

say $tx->dump;
say to_format [hex => $tx->to_serialized];

__END__

=head1 P2TR transaction example

A simple transaction spending one P2TR input with key spend path and produces
a single P2TR output.

Fee rate is (inaccurately) approximated. To set exact fee rate sign the
transaction, calculate fee based on its virtual size and then sign again
- changing the value of the output invalidates previous signatures.

This code was used to produce testnet transaction:
L<https://mempool.space/testnet4/tx/269bb63af0f1c3b29e2004540464622eef46c40a781b3ca440f03dac1fe3f02a>

