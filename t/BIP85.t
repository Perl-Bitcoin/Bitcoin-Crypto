use Test2::V0;
use Bitcoin::Crypto::BIP85;
use Bitcoin::Crypto qw(btc_extprv);
use Bitcoin::Crypto::Util qw(to_format);

subtest 'should derive_entropy' => sub {
	my $bip85 = Bitcoin::Crypto::BIP85->new(
		key => btc_extprv->from_serialized(
			[
				base58 =>
					'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb'
			]
		),
	);

	is to_format [hex => $bip85->derive_entropy(q{m/83696968'/0'/0'})],
		'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7',
		'entropy index 0 derived ok';

	is to_format [hex => $bip85->derive_entropy(q{m/83696968'/0'/0'}, 32)],
		'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0',
		'truncated entropy index 0 ok';

	is to_format [hex => $bip85->derive_entropy(q{m/83696968'/0'/0'}, 80)],
		'b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111',
		'stretched entropy index 0 ok';

	is to_format [hex => $bip85->derive_entropy(q{m/83696968'/0'/1'})],
		'70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e',
		'entropy index 1 derived ok';
};

subtest 'should derive a mnemonic according to BIP39 application of BIP85' => sub {
	my $bip85 = Bitcoin::Crypto::BIP85->new(
		key => btc_extprv->from_serialized(
			[
				base58 =>
					'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb'
			]
		),
	);

	# check words
	is $bip85->derive_mnemonic(words => 12),
		'girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose', '12 words ok';
	is $bip85->derive_mnemonic(words => 18),
		'near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token',
		'18 words ok';
	is $bip85->derive_mnemonic(words => 24),
		'puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano',
		'24 words ok';

	# check index
	is $bip85->derive_mnemonic(words => 12, index => 1),
		'mystery car occur shallow stable order number feature else best trigger curious', '12 words index 1 ok';
};

done_testing;

