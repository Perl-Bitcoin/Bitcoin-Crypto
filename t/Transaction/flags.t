use Test2::V0;
use Bitcoin::Crypto qw(btc_transaction btc_script btc_utxo);
use Bitcoin::Crypto::Transaction::Flags;

use lib 't/lib';
use TransactionStore;

my $p2sh_p2wpkh =
	'02000000000101f36d649153edbd05024632ee5301d85b2e6cbaeb4c87dd27588486e91d3a71e60100000017160014c188c6f016e332b74ed1cd9459111f53b581ecf2fdffffff0284d80100000000001600142fc521f81034f6937a0fe29488f630e2952d5a69931ddd030000000017a914fc85c6aa880c616db537a873607f610256285d7d87024730440220797c7518dcae53312f47327c79a261ee51e70fa063a17f15da0db35b61ce14ce022064ace894fb017e515578250b76834981d8aba80b7a37a2cbefca57cd84a0b9e70121023634e479b58c58cb8cc1650684729c5c58765b245a4844aee2e39bca4da3f3f900000000';

my $p2pk_low_s_sig =
	'010000000173805864da01f15093f7837607ab8be7c3705e29a9d4a12c9116d709f8911e590100000049483045022052ffc1929a2d8bd365c6a2a4e3421711b4b1e1b8781698ca9075807b4227abcb0221009984107ddb9e3813782b095d0d84361ed4c76e5edaf6561d252ae162c2341cfb01ffffffff0200e1f50500000000434104baa9d36653155627c740b3409a734d4eaf5dcca9fb4f736622ee18efcf0aec2b758b2ec40db18fbae708f691edb2d4a2a3775eb413d16e2e3c0f8d4c69119fd1ac009ce4a60000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000';

my $taproot =
	'02000000000101413e6ebeb138f2bcd921e1f4916638f66a17ac6d89eeb887a0f783a15ca2bffe1000000000010000800180d28e000000000016001486e12984f936a16300c63dd62192efbc61be4b680140552d631e974ec9701b70ec27331a3a349d644515a6672e88063d9ddd14687fa7b57a2c12841ec6df443f2b04c07cb8e2036b90edbe7cd17ea7765d1810334f1300000000';

my $p2wsh_multisig =
	'01000000000101ace38e461a7764db1869b1e93311021081e26c60f66e2218c0810c4a233a5f610000000000ffffffff027082030000000000160014187ef34cb1927aad00a8d9707c4941a0712bdfda30750000000000001600145e66c4a1f0869ce974afbd7656a61b02c3518023040047304402202e5663de161a6aaaf3a51cdcbed1eac7a3d1edf10b04beb2a1e327e64598e0bd02205047bdf829db952246a847a495989a3b0a9e7c54d689bb3583c269adcb92e895014730440220438bf9d3eec5dcf18c3f6ccd25ecf488c1edff2b7a05bb6bf3f73ec3dbc1d787022016c3a2452375c84cabb783e671a34e8986a53c075f21e5c4922813e9ecedf0930147522103593408ee5b34522528ddc675c2105b11a220f5d0ad68c79cb3cee6bd751b6f1021032e8231e4daa047f13e2f568836b10f81c55d37b26fdafd5084d8be29fda9baa152ae00000000';

subtest 'checking new_empty' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(p2sh => !!1);

	ok $flags->p2sh, 'p2sh ok';
	ok !$flags->nulldummy, 'nulldummy ok';
};

subtest 'checking p2sh' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(p2sh => !!0);
	my $tx = btc_transaction->from_serialized([hex => $p2sh_p2wpkh]);

	# modify signature script to test ignoring p2sh
	$tx->inputs->[0]->set_signature_script(
		btc_script->new
			->push([hex => 'deadbeef'])
			->push([hex => '0014c188c6f016e332b74ed1cd9459111f53b581ecf2'])
	);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled p2sh ok';
};

subtest 'checking strict_signatures' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(strict_signatures => !!0);
	my $tx = btc_transaction->from_serialized([hex => $p2pk_low_s_sig]);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled strict signatures ok';
};

subtest 'checking nulldummy' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(nulldummy => !!0);
	my $tx = btc_transaction->from_serialized([hex => $p2wsh_multisig]);

	# modify nulldummy element
	$tx->inputs->[0]->witness->[0] = "\x01";

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled nulldummy ok';
};

subtest 'checking checklocktimeverify' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(checklocktimeverify => !!0);

	my $utxo = btc_utxo->new(
		txid => "\x01" x 32,
		output_index => 0,
		output => {
			locking_script => btc_script->new
				->add('OP_CHECKLOCKTIMEVERIFY')
				->add('OP_1'),
			value => 500,
		}
	);

	my $tx = btc_transaction->new;

	# OP_CHECKLOCKTIMEVERIFY marks script as invalid on negative number
	$tx->add_input(
		utxo => $utxo,
		signature_script => btc_script->new
			->push_number(-1),
	);

	$tx->add_output(
		locking_script => "\01",
		value => 500,
	);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled checklocktimeverify ok';
};

subtest 'checking checksequenceverify' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(checksequenceverify => !!0);

	my $utxo = btc_utxo->new(
		txid => "\x01" x 32,
		output_index => 0,
		output => {
			locking_script => btc_script->new
				->add('OP_CHECKSEQUENCEVERIFY')
				->add('OP_1'),
			value => 500,
		}
	);

	my $tx = btc_transaction->new;

	# OP_CHECKSEQUENCEVERIFY marks script as invalid on negative number
	$tx->add_input(
		utxo => $utxo,
		signature_script => btc_script->new
			->push_number(-1),
	);

	$tx->add_output(
		locking_script => "\01",
		value => 500,
	);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled checksequenceverify ok';
};

subtest 'checking segwit' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(segwit => !!0);
	my $tx = btc_transaction->from_serialized([hex => $p2sh_p2wpkh]);

	# modify witness to test ignoring segwit
	$tx->inputs->[0]->set_witness([[hex => 'deadbeef']]);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled segwit ok';
};

subtest 'checking taproot' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(taproot => !!0);
	my $tx = btc_transaction->from_serialized([hex => $taproot]);

	# modify witness to test ignoring taproot
	$tx->inputs->[0]->set_witness([[hex => 'deadbeef']]);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled taproot ok';
};

done_testing;

