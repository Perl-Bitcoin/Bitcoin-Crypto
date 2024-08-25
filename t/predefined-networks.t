use Test2::V0;
use Bitcoin::Crypto qw(btc_extprv btc_prv);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

# all test data will use this mnemonic and BIP44 derivation path
# specify values for the first derived account (m/44'/0'/x')
my $master_key = btc_extprv->from_mnemonic(
	'anger head salmon dress include render fatigue remain torch bind piece usage loud leopard corn'
);

my @predefined_networks = (
	{
		id => 'bitcoin',
		account_prv =>
			'xprv9ymgBmhZeeUTM5ijVkRMvVjoVhrofguejSm6EdXCWfAiusG15YofVwYTTEaA1hxUVe37dGL6Rq5h3VR59F3WjKHveVmieyq8E1LfFQT8b61',
		account_pub =>
			'xpub6Cm2bHETV22kZZoCbmxNHdgY3jhJ59dW6fgh31vp4zhhnfb9d67v3jrwJUS63atPcTj9sWoAdiJBAarZ2EGniSr4F7pBgREPUhsxcD7snYv',
		wif => 'L34iNYx2ocTTBrYTmbB8E8uaPYCFYrBgackz6QjDC6xvu4uqKXDG',
		address => '12Y6osd52Vps2qeEQ7GfAt7VDecmvEoaBV',
		compat_address => '3L5KcFnfEGJq2ugCAox55MCRX28cYRrpwh',
		segwit_address => 'bc1qzrvauakga3w4zzpsa6rkppyvvt85rv062vjkrg',
	},

	{
		id => 'bitcoin_testnet',
		account_prv =>
			'tprv8fTqCYXFU7MCArvB8n529P5qBqb4kBjkB3DtfN86WazW6wxhmnAHqcbm3FuLeuTmdTqXm6MqfxeyzCyh4BRUNbsFc6CzzibrfvfUu3EKddZ',
		account_pub =>
			'tpubDC9sLxZVcV2s4Kwy2RjcYnjwks6zuWvekLpfwtAPvrntwSDUQAyt27DdDRHwDL63NxX7RuXD7Bgw7Qaf4vvssYdcVuv5MfvkFjZiDiRsfC7',
		wif => 'cSjWwKXeprZizXdALthnrVSV8erAx4DBfyZKPtRFTf5Q1shtJz5W',
		address => 'mv7vD5X5PuMhFnFJg2eLEi92hCtL6WgcSB',
		compat_address => '2MtGBzvu6U1LFYtHjr5RYDuYzyHDtkpvxRR',
		segwit_address => 'tb1q5qhfgxt3zgpxj66tmt42splx3anv7f3wgrscta',
	},

	{
		id => 'dogecoin',
		account_prv =>
			'dgpv58fwwrKerCX4XqSYsix1UDyEFb1WXXkTjXMvdoQng5WwvdqNUrvydkx6WcyAJTbdCT1rnPhigNj2V2YiZdbVyWfXgJtZ14LjGrfVfnffgcn',
		account_pub =>
			'dgub8sYyHYFYQMBPph6huxZyb5Wpi9P9MenB2898nuomUCZxUgx4tdUkH4Mk5rBd5Hk36392xhsuVm72pZKA2Wc4i18zgFfi4PfgCemw67EiSbP',
		wif => 'QVVTD1eyReofUsNjiPoYaLTCNanr2xUx6Yx11R4H9q4TayY433BC',
		address => 'D6V34ccS3k2o5rwC5NuYomKmbbMTgr1NQt',
	},

	{
		id => 'dogecoin_testnet',
		account_prv =>
			'tprv8fTqCYXFU7MCArvB8n529P5qBqb4kBjkB3DtfN86WazW6wxhmnAHqcbm3FuLeuTmdTqXm6MqfxeyzCyh4BRUNbsFc6CzzibrfvfUu3EKddZ',
		account_pub =>
			'tpubDC9sLxZVcV2s4Kwy2RjcYnjwks6zuWvekLpfwtAPvrntwSDUQAyt27DdDRHwDL63NxX7RuXD7Bgw7Qaf4vvssYdcVuv5MfvkFjZiDiRsfC7',
		wif => 'cjtn5eFTBAPzwZehT3VaSqdTdXFUctkdzroaWo7SScapaYA6iysa',
		address => 'nio8BJ7epGHSteXUisJyCxgbxDQDX41Zw5',
	},

	{
		id => 'pepecoin',
		account_prv =>
			'dgpv57XkTszWUiM7L8xUAvXaj7evMpYFKcdYCQihFKwM1vyvEyGBSEJ8NuPU8aSgoNkfzPJ92KvUyrwAvJPfDzE17cF1FkSaVEhmkXkqrg7qwN6',
		account_pub =>
			'dgub8rQmoZvQ2s1SczcdDA9YqyCWpNut9jfFV1VuQSLKp42vo2Nsqzqu2Co7ho4pGi9QFs49a6595R5zmfdmgDR95TK6msW2oQi7KSCaqURZYwi',
		wif => 'QVvidFn85YHvjxzJj1M4y1tyF1k71jyabE7zBT6rcwgk3mqzUvQ4',
		address => 'PbMTSd5ko3YtgF8Y4F95VoYEM5tNaYeWQk',
	},

	{
		id => 'pepecoin_testnet',
		account_prv =>
			'tprv8fTqCYXFU7MCArvB8n529P5qBqb4kBjkB3DtfN86WazW6wxhmnAHqcbm3FuLeuTmdTqXm6MqfxeyzCyh4BRUNbsFc6CzzibrfvfUu3EKddZ',
		account_pub =>
			'tpubDC9sLxZVcV2s4Kwy2RjcYnjwks6zuWvekLpfwtAPvrntwSDUQAyt27DdDRHwDL63NxX7RuXD7Bgw7Qaf4vvssYdcVuv5MfvkFjZiDiRsfC7',
		wif => 'cn445egncJLLcv64dJ7C3TkPu5RFJUUv6tpod9riNfEpRFS6TDoq',
		address => 'nXcqZp5BGKxqHx5UTA8F8x45Dqa93Jb3kK',
	},
);

my %default_mapped = map { $_ => 1 } Bitcoin::Crypto::Network->find;

for my $case (@predefined_networks) {
	subtest "testing $case->{id}" => sub {
		ok defined $default_mapped{$case->{id}}, 'network available ok';

		$master_key->set_network($case->{id});

		# Dogecoin and Pepecoin share the same WIF bit, so we need to set the default network explicitly
		Bitcoin::Crypto::Network->get($case->{id})->set_default;

		if ($case->{account_prv}) {
			my $derived = $master_key->derive_key_bip44(get_account => 1);
			is to_format [base58 => $derived->to_serialized], $case->{account_prv},
				'account extended private key ok';
			is to_format [base58 => $derived->get_public_key->to_serialized], $case->{account_pub},
				'account extended public key ok';
		}

		if ($case->{wif}) {
			my $prvkey = btc_prv->from_wif($case->{wif});
			is $prvkey->network->id, $case->{id}, 'network id ok';

			is $prvkey->get_public_key->get_legacy_address, $case->{address}, 'address ok';

			if ($case->{segwit_address}) {
				is $prvkey->get_public_key->get_compat_address, $case->{compat_address}, 'compat address ok';
				is $prvkey->get_public_key->get_segwit_address, $case->{segwit_address}, 'segwit address ok';
			}
		}
	};
}

is scalar keys %default_mapped, scalar @predefined_networks, 'network count ok';

done_testing;

