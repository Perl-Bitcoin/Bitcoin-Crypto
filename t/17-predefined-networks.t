use v5.10;
use strict;
use warnings;
use Test::More;

use Bitcoin::Crypto qw(btc_extprv btc_prv);
use Bitcoin::Crypto::Network;

# all test data will use this mnemonic and BIP44 derivation path
# specify values for the first derived account (m/44'/0'/x')
my $master_key = btc_extprv->from_mnemonic('anger head salmon dress include render fatigue remain torch bind piece usage loud leopard corn');

my %predefined_networks = (
	bitcoin => {
		account_prv => 'xprv9ymgBmhZeeUTM5ijVkRMvVjoVhrofguejSm6EdXCWfAiusG15YofVwYTTEaA1hxUVe37dGL6Rq5h3VR59F3WjKHveVmieyq8E1LfFQT8b61',
		account_pub => 'xpub6Cm2bHETV22kZZoCbmxNHdgY3jhJ59dW6fgh31vp4zhhnfb9d67v3jrwJUS63atPcTj9sWoAdiJBAarZ2EGniSr4F7pBgREPUhsxcD7snYv',

		wif => 'L34iNYx2ocTTBrYTmbB8E8uaPYCFYrBgackz6QjDC6xvu4uqKXDG',
		address => '12Y6osd52Vps2qeEQ7GfAt7VDecmvEoaBV',
		compat_address => '3L5KcFnfEGJq2ugCAox55MCRX28cYRrpwh',
		segwit_address => 'bc1qzrvauakga3w4zzpsa6rkppyvvt85rv062vjkrg',
	},

	bitcoin_testnet => {
		account_prv => 'tprv8fTqCYXFU7MCArvB8n529P5qBqb4kBjkB3DtfN86WazW6wxhmnAHqcbm3FuLeuTmdTqXm6MqfxeyzCyh4BRUNbsFc6CzzibrfvfUu3EKddZ',
		account_pub => 'tpubDC9sLxZVcV2s4Kwy2RjcYnjwks6zuWvekLpfwtAPvrntwSDUQAyt27DdDRHwDL63NxX7RuXD7Bgw7Qaf4vvssYdcVuv5MfvkFjZiDiRsfC7',

		wif => 'cSjWwKXeprZizXdALthnrVSV8erAx4DBfyZKPtRFTf5Q1shtJz5W',
		address => 'mv7vD5X5PuMhFnFJg2eLEi92hCtL6WgcSB',
		compat_address => '2MtGBzvu6U1LFYtHjr5RYDuYzyHDtkpvxRR',
		segwit_address => 'tb1q5qhfgxt3zgpxj66tmt42splx3anv7f3wgrscta',
	},

	dogecoin => {
		account_prv => 'dgpv58fwwrKerCX4XqSYsix1UDyEFb1WXXkTjXMvdoQng5WwvdqNUrvydkx6WcyAJTbdCT1rnPhigNj2V2YiZdbVyWfXgJtZ14LjGrfVfnffgcn',
		account_pub => 'dgub8sYyHYFYQMBPph6huxZyb5Wpi9P9MenB2898nuomUCZxUgx4tdUkH4Mk5rBd5Hk36392xhsuVm72pZKA2Wc4i18zgFfi4PfgCemw67EiSbP',

		wif => 'QVVTD1eyReofUsNjiPoYaLTCNanr2xUx6Yx11R4H9q4TayY433BC',
		address => 'D6V34ccS3k2o5rwC5NuYomKmbbMTgr1NQt',
	},

	dogecoin_testnet => {
		account_prv => 'tprv8fTqCYXFU7MCArvB8n529P5qBqb4kBjkB3DtfN86WazW6wxhmnAHqcbm3FuLeuTmdTqXm6MqfxeyzCyh4BRUNbsFc6CzzibrfvfUu3EKddZ',
		account_pub => 'tpubDC9sLxZVcV2s4Kwy2RjcYnjwks6zuWvekLpfwtAPvrntwSDUQAyt27DdDRHwDL63NxX7RuXD7Bgw7Qaf4vvssYdcVuv5MfvkFjZiDiRsfC7',

		wif => 'cjtn5eFTBAPzwZehT3VaSqdTdXFUctkdzroaWo7SScapaYA6iysa',
		address => 'nio8BJ7epGHSteXUisJyCxgbxDQDX41Zw5',
	},
);

my %default_mapped = map { $_ => 1 } Bitcoin::Crypto::Network->find;
my $count = scalar keys %default_mapped;

for my $network_id (keys %predefined_networks) {
	subtest "testing $network_id" => sub {
		ok defined $default_mapped{$network_id}, "network available ok";

		my %tdata = %{$predefined_networks{$network_id}};
		$master_key->set_network($network_id);

		if ($tdata{account_prv}) {
			my $derived = $master_key->derive_key_bip44(get_account => 1);
			is $derived->to_serialized_base58, $tdata{account_prv}, 'account extended private key ok';
			is $derived->get_public_key->to_serialized_base58, $tdata{account_pub}, 'account extended public key ok';
		}

		if ($tdata{wif}) {
			my $prvkey = btc_prv->from_wif($tdata{wif});
			is $prvkey->network->id, $network_id, 'network id ok';

			is $prvkey->get_public_key->get_legacy_address, $tdata{address}, 'address ok';

			if ($tdata{segwit_address}) {
				is $prvkey->get_public_key->get_compat_address, $tdata{compat_address}, 'compat address ok';
				is $prvkey->get_public_key->get_segwit_address, $tdata{segwit_address}, 'segwit address ok';
			}
		}
	};
}

is scalar keys %default_mapped, scalar keys %predefined_networks, 'network count ok';

done_testing;

