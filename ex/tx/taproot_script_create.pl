use v5.14;
use warnings;

use Bitcoin::Crypto qw(btc_transaction btc_utxo btc_prv btc_script_tree btc_tapscript btc_psbt);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Key::NUMS;
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Constants qw(:script);

Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default;

my $tx = btc_transaction->new;

# this is the data of the transaction which created the output we want to spend
btc_utxo->extract(
	[
		hex =>
			'01000000000101632e71989d3acfc9e780257ebb5ae919707c00ae34d94a83383fb05be0a8c26e0000000000ffffffff0164a00700000000002251205c271af22d6439cf7acb62cdd37cedcfb672b51fb66bda0a1a342994c4a420ec01402e6ca8396d75de6074a0bb69acc8876eef876b8ec348c77f2b1cc2a790331aa143d255a9d573a14e7b10eea6942bc88b96fc73cdfe02b5b85e095d07d03e778f00000000'
	]
);

# input must point to the transaction output above - transaction ID and output number
$tx->add_input(
	utxo => [[hex => '269bb63af0f1c3b29e2004540464622eef46c40a781b3ca440f03dac1fe3f02a'], 0],
);

# taproot script tree. Each script must be a tapscript.
# this is a binary tree, so if more levels were to be added, they must be
# inside nested array references.
my $tree = btc_script_tree->new(
	tree => [

		# spend with signatures, functionally the same as 2-out-of-3 multisig
		{
			leaf_version => TAPSCRIPT_LEAF_VERSION,
			script => btc_tapscript->new
				->add('OP_0')
				->push([hex => '06ae261166310f1b1f2a12a984cf3e04244e0b577995432e155b2af27eb75822'])
				->add('OP_CHECKSIGADD')
				->push([hex => 'e5a8dd8c73c16d2e813e0917696da6c45e323e7a57815f78f814df755e064317'])
				->add('OP_CHECKSIGADD')
				->push([hex => '381897e4c44548eb6677ec295bf8ccedccaad6362ee210d1d9c3b4858d12f957'])
				->add('OP_CHECKSIGADD')
				->add('OP_2')
				->add('OP_NUMEQUAL'),
		},

		# spend with lucky number 13
		{
			leaf_version => TAPSCRIPT_LEAF_VERSION,
			script => btc_tapscript->new
				->add('OP_13')
				->add('OP_NUMEQUAL')
		},
	],
);

# create NUMS key to disable key spend path. This output will only be spendable
# by calling one of the scripts above.
my $nums = Bitcoin::Crypto::Key::NUMS->new;
my $public = $nums->get_public_key;

# send all the coins to this address. By adding $tree as an argument, we
# specify a script path spend for this address. Addresses with script path
# spend are visually the same as those without it.
$tx->add_output(
	locking_script => [address => $public->get_taproot_address($tree)],
	value => 0,
);

# calculate fee and set the value of first output. Unsigned tx virtual size is
# used, so the real fee rate will be approx two times smaller
my $wanted_fee_rate = 2;
$tx->outputs->[0]->set_value($tx->fee - int($tx->virtual_size * $wanted_fee_rate));

# create a PSBT with tree and public key saved for later
my $psbt = btc_psbt->new;
$psbt->add_field(
	type => 'PSBT_GLOBAL_UNSIGNED_TX',
	value => $tx,
);
$psbt->add_field(
	type => 'PSBT_OUT_TAP_INTERNAL_KEY',
	value => $public,
	index => 0,
);
$psbt->add_field(
	type => 'PSBT_OUT_TAP_TREE',
	value => $tree,
	index => 0,
);

# sign all inputs with the corresponding private keys
btc_prv->from_wif('cSYVAqqhPDQBwuLXuaspQiEi4sHPED6j8W1JyV8fHBSDkiKNeeG7')->sign_transaction($tx, signing_index => 0);

# verify the correctness of the transaction. Throws an exception on failure
$tx->verify;

say $tx->dump;
say 'NUMS tweak: ' . to_format [hex => $nums->tweak];
say 'PSBT with tree and internal key: ' . to_format [base64 => $psbt->to_serialized];
say 'Serialized transaction: ' . to_format [hex => $tx->to_serialized];

__END__

=head1 P2TR script output creation example

A transaction spending one P2TR input with key spend path and produces a
single P2TR output that contains a couple of scripts. Example uses "Nothing up
my sleeve" point to disable key spend path.

To store the tree and public key for later, we create a PSBT with
C<PSBT_OUT_TAP_TREE> and C<PSBT_OUT_TAP_INTERNAL_KEY> keys. The exact same
taproot tree and public key will be required to spend.

NUMS tweak is printed and can be used to prove that this key is unspendable.

Fee rate is (inaccurately) approximated. To set exact fee rate sign the
transaction, calculate fee based on its virtual size and then sign again
- changing the value of the output invalidates previous signatures.

This code was used to produce testnet transaction:
L<https://mempool.space/testnet4/tx/36feb985660ec0a3c874952b8dd0b7f4b3d39399f0b506f3dc72b9f6e7f81d80>

Note that since it uses a freshly-generated NUMS key on every run, the
generated transaction id will vary.

