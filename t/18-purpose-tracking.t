use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_extprv btc_extpub);
use Bitcoin::Crypto::Util qw(to_format);

my $master_key = btc_extprv->from_mnemonic(
	'anger head salmon dress include render fatigue remain torch bind piece usage loud leopard corn'
);

my @cases = (
	sub { shift },
	sub { shift->derive_key_bip44(get_from_account => 1) },
	sub { shift->get_public_key },
	sub { shift->get_basic_key },
	sub { shift->get_public_key->get_basic_key },
	sub { shift->get_basic_key->get_public_key },
);

my %expected_serializations = (
	44 => [
		'xprv9ymgBmhZeeUTM5ijVkRMvVjoVhrofguejSm6EdXCWfAiusG15YofVwYTTEaA1hxUVe37dGL6Rq5h3VR59F3WjKHveVmieyq8E1LfFQT8b61',
		'xpub6Cm2bHETV22kZZoCbmxNHdgY3jhJ59dW6fgh31vp4zhhnfb9d67v3jrwJUS63atPcTj9sWoAdiJBAarZ2EGniSr4F7pBgREPUhsxcD7snYv'
	],
	49 => [
		'yprvAJ3KMab6mwJPX5L1nFm3NtXinPD1saRvLJMy9SKqKKCvX82gqG5635v37FbT23mbdudnaZ7REZjvWZRsPz95y4XVY9Kf2nfbBb5pi4LqTGS',
		'ypub6X2fm67zcJrgjZQUtHJ3k2UTLR3WH39mhXHZwpjSsejuPvMqNoPLatEWxYqWmDUZL7JWLcQgKAnZ3ekpA54GibTymE8Y4JsfpKt6EPmoDLH'
	],
	84 => [
		'zprvAe3TndrapNEpcCLVUU3qE2RVonXrgtnEjmmZjX3LeMqJueDNBBpX9WpkwYYNi2UrjrJifn48Fcqwx4WUBKi1LmGtwu3igEwdyFmM3BaqDko',
		'zpub6s2pC9PUejo7pgQxaVaqbANEMpNM6MW66zhAXuSxChNHnSYWij8mhK9EnqU2iKrPaDY4vokUVtVvZmTE6RH21AQBfBZe5gyavkKPSYTVnvq'
	],
);

for my $purpose (qw(44 49 84)) {
	my $derived = $master_key->derive_key_bip44(purpose => $purpose, get_account => 1);

	subtest "testing derivation for purpose: $purpose" => sub {
		for my $case (@cases) {
			is $case->($derived)->purpose, $purpose, 'purpose perserved ok';
		}

		my ($serprv, $serpub) = @{$expected_serializations{$purpose}};
		is to_format [base58 => $derived->to_serialized], $serprv, 'serialized prv ok';
		is to_format [base58 => $derived->get_public_key->to_serialized], $serpub, 'serialized pub ok';

		is btc_extprv->from_serialized([base58 => $serprv])->purpose, $purpose, 'unserialized prv purpose ok';
		is btc_extprv->from_serialized([base58 => $serprv])->to_serialized, $derived->to_serialized,
			'unserialized prv ok';
		is btc_extpub->from_serialized([base58 => $serpub])->purpose, $purpose, 'unserialized pub purpose ok';
		is btc_extpub->from_serialized([base58 => $serpub])->to_serialized, $derived->get_public_key->to_serialized,
			'unserialized pub ok';
	};

	subtest "testing inability to generate wrong address types for purpose: $purpose" => sub {
		my $first = $derived->derive_key_bip44(get_from_account => 1)->get_basic_key->get_public_key;

		if ($purpose eq 44) {
			lives_ok { $first->get_legacy_address };
		}
		else {
			dies_ok { $first->get_legacy_address };
		}

		if ($purpose eq 49) {
			lives_ok { $first->get_compat_address };
		}
		else {
			dies_ok { $first->get_compat_address };
		}

		if ($purpose eq 84) {
			lives_ok { $first->get_segwit_address };
		}
		else {
			dies_ok { $first->get_segwit_address };
		}
	};

	subtest 'testing purpose clearing' => sub {
		my $first = $derived->derive_key_bip44(get_from_account => 1)->get_basic_key->get_public_key;

		$first->clear_purpose;
		lives_ok { $first->get_legacy_address };
		lives_ok { $first->get_compat_address };
		lives_ok { $first->get_segwit_address };
	};
}

done_testing;

