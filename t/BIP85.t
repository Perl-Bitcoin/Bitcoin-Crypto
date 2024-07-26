use Test2::V0;
use Bitcoin::Crypto::BIP85;
use Bitcoin::Crypto qw(btc_extprv);
use Bitcoin::Crypto::Util qw(to_format);

subtest 'should derive_entropy' => sub {
	my $bip85 = Bitcoin::Crypto::BIP85->new(
		key => btc_extprv->from_serialized([base58 => 'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb']),
	);

	is to_format [hex => $bip85->derive_entropy(q{m/83696968'/0'/0'})], 'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7', 'entropy index 0 derived ok';

	is to_format [hex => $bip85->derive_entropy(q{m/83696968'/0'/1'})], '70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e', 'entropy index 1 derived ok';
};


done_testing;

