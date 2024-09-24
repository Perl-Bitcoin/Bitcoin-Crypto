use Test2::V0;
use Bitcoin::Crypto qw(btc_extprv);
use Bitcoin::Crypto::Util qw(to_format);

# Data from:
# https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors

my @cases = (
	{
		bip44 => {
			purpose => Bitcoin::Crypto::Constants::bip44_taproot_purpose,
			index => 1,
		},
		xprv =>
			'xprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ',
		xpub =>
			'xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX',
		internal_key => '83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145',
		output_key => 'a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb',
		scriptPubKey => '5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb',
		address => 'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh',
	},
	{
		bip44 => {
			purpose => Bitcoin::Crypto::Constants::bip44_taproot_purpose,
			change => 1,
		},
		xprv =>
			'xprvA3Ln3Gt3aphvUgzgEDT8vE2cYqb4PjFfpmbiFKphxLg1FjXQpkAk5M1ZKDY15bmCAHA35jTiawbFuwGtbDZogKF1WfjwxML4gK7WfYW5JRP',
		xpub =>
			'xpub6GL8SnQwRCGDhB59LEz9HMyM6sRYoByXBzXK3iEKWgCz8XrZNHUzd9L3AUBELW5NzA7dEFvMas1F84TuPH3xqdUA5tumaGWFgihJzWytXe3',
		internal_key => '399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef',
		output_key => '882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc',
		scriptPubKey => '5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc',
		address => 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7',
	},
);

my $master = btc_extprv->from_mnemonic(
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
);

foreach my $case_ind (0 .. $#cases) {
	subtest "should pass case index $case_ind" => sub {
		my $case = $cases[$case_ind];
		my $key = $master->derive_key_bip44(%{$case->{bip44}});

		is to_format [base58 => $key->to_serialized], $case->{xprv}, 'extended private key ok';
		is to_format [base58 => $key->get_public_key->to_serialized], $case->{xpub}, 'extended public key ok';

		$key = $key->get_basic_key;
		#is to_format [hex => $key->get_public_key->to_serialized], $case->{internal_key}, 'private key ok';
		is $key->get_public_key->get_address, $case->{address}, 'address ok';
	};
}

done_testing;

