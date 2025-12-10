use Test2::V0;
use Bitcoin::Crypto qw(btc_prv btc_transaction btc_script btc_utxo);
use Bitcoin::Crypto::Transaction::Flags;
use Bitcoin::Crypto::Constants qw(:sighash);

use lib 't/lib';
use TransactionStore;

# interesting private key - it was found to have first zero byte when turned
# into public key (0x0200)
my $privkey = btc_prv->from_serialized("\xf6");

my $p2sh_p2ms =
	'02000000024dcae1b1f8de0acabbe0f92ff985016e7fdfb468afebcc5eb6f01b40af67b80900000000fdfd0000483045022100b04730bfdaf5ef3f1e2038474fec6abe67e989cb15c69b4dadc0769f07e5245202202ef218548bf8caa3682a808f0c6f6da48ed203fe052ab036e03b332da7e35a31014730440220450a66c8f29e50dc53f883cf8a372cb06c49be8ee2a04276d7befd982c252e8702204353835fcfae1a561f50212fa69ef117c66e14d9d513f7057e2884b86174f130014c69522103c0e8a0663fe1c4d6c6ff91421498dfc443af470494ccf02949fd1a9931e403db210307cc351c1c63b02229807c6177d0ac1bd2345dac305cce870ab7b51ef2c964ef2103147c2a372e4bc2893c7367b9b9c8cdc7aca7f154fa83899525912ab2547793a953aeffffffff3e2b2087982c6c5f1d8214f3af4d8d82931937cad33ee950d72737dfbdd6c86f01000000fdfd000047304402202334e2cb865e290eb4cf2e49e4abf7ea9adbc66177ac8ea7abf373f45240522902203c335e1875adc1c62beabf4f413efdcc4fb917fee7d711f4e65c208537d578db01483045022100eb5aec400cd9833666a61af852072e6d83d32e47465e15efb2261232c788f875022045fef9acea44e51bef226cca4edb39d3e8d87fc124ba2d42f4d0e800b9535a14014c69522102851bdb1b3bbbe3d58cb0ddc949a71cb743b6a27730d0af3b45e6acb01ccc97472102b70942697c82cd560293df146e61002777c222a75bd0320176366f4b61eec61921027336b42972aa0abe1b6d2ecb0d37ea8489b9535940336077d1a2d5c21657df2153aeffffffff02729638000000000017a914d22da5b4190f2f834d6228d9bcbcf5fbf83080fe87553a2600000000001976a914723707ed5fc05e6acfbc8eabb89679813296230d88ac00000000';

my $p2sh_p2wpkh =
	'02000000000101f36d649153edbd05024632ee5301d85b2e6cbaeb4c87dd27588486e91d3a71e60100000017160014c188c6f016e332b74ed1cd9459111f53b581ecf2fdffffff0284d80100000000001600142fc521f81034f6937a0fe29488f630e2952d5a69931ddd030000000017a914fc85c6aa880c616db537a873607f610256285d7d87024730440220797c7518dcae53312f47327c79a261ee51e70fa063a17f15da0db35b61ce14ce022064ace894fb017e515578250b76834981d8aba80b7a37a2cbefca57cd84a0b9e70121023634e479b58c58cb8cc1650684729c5c58765b245a4844aee2e39bca4da3f3f900000000';

my $p2pk_low_s_sig =
	'010000000173805864da01f15093f7837607ab8be7c3705e29a9d4a12c9116d709f8911e590100000049483045022052ffc1929a2d8bd365c6a2a4e3421711b4b1e1b8781698ca9075807b4227abcb0221009984107ddb9e3813782b095d0d84361ed4c76e5edaf6561d252ae162c2341cfb01ffffffff0200e1f50500000000434104baa9d36653155627c740b3409a734d4eaf5dcca9fb4f736622ee18efcf0aec2b758b2ec40db18fbae708f691edb2d4a2a3775eb413d16e2e3c0f8d4c69119fd1ac009ce4a60000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000';

my $taproot =
	'02000000000101413e6ebeb138f2bcd921e1f4916638f66a17ac6d89eeb887a0f783a15ca2bffe1000000000010000800180d28e000000000016001486e12984f936a16300c63dd62192efbc61be4b680140552d631e974ec9701b70ec27331a3a349d644515a6672e88063d9ddd14687fa7b57a2c12841ec6df443f2b04c07cb8e2036b90edbe7cd17ea7765d1810334f1300000000';

my $p2wsh_multisig =
	'01000000000101ace38e461a7764db1869b1e93311021081e26c60f66e2218c0810c4a233a5f610000000000ffffffff027082030000000000160014187ef34cb1927aad00a8d9707c4941a0712bdfda30750000000000001600145e66c4a1f0869ce974afbd7656a61b02c3518023040047304402202e5663de161a6aaaf3a51cdcbed1eac7a3d1edf10b04beb2a1e327e64598e0bd02205047bdf829db952246a847a495989a3b0a9e7c54d689bb3583c269adcb92e895014730440220438bf9d3eec5dcf18c3f6ccd25ecf488c1edff2b7a05bb6bf3f73ec3dbc1d787022016c3a2452375c84cabb783e671a34e8986a53c075f21e5c4922813e9ecedf0930147522103593408ee5b34522528ddc675c2105b11a220f5d0ad68c79cb3cee6bd751b6f1021032e8231e4daa047f13e2f568836b10f81c55d37b26fdafd5084d8be29fda9baa152ae00000000';

#####################
### METHOD CHECKS ###
#####################

subtest 'checking new_empty' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(p2sh => !!1);

	ok $flags->p2sh, 'p2sh ok';
	ok !$flags->null_dummy, 'null_dummy ok';
};

subtest 'checking new_full' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_full(null_fail => !!0);

	ok !$flags->null_fail, 'null_fail ok';
	ok $flags->clean_stack, 'clean_stack ok';
};

subtest 'checking verify_standard' => sub {
	my $tx = btc_transaction->from_serialized([hex => $p2pk_low_s_sig]);

	ok lives { $tx->verify }, 'checking with consensus rules ok';
	ok dies { $tx->verify_standard }, 'checking with standard rules ok';
};

#############################
### CONSENSUS FLAG CHECKS ###
#############################

subtest 'checking p2sh' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(p2sh => !!0);
	my $tx = btc_transaction->from_serialized([hex => $p2sh_p2ms]);

	# modify signature script to test ignoring p2sh
	$tx->inputs->[0]->set_signature_script(
		btc_script->new
			->push([hex => 'deadbeef'])
			->push(
				[
					hex =>
					'522103c0e8a0663fe1c4d6c6ff91421498dfc443af470494ccf02949fd1a9931e403db210307cc351c1c63b02229807c6177d0ac1bd2345dac305cce870ab7b51ef2c964ef2103147c2a372e4bc2893c7367b9b9c8cdc7aca7f154fa83899525912ab2547793a953ae '
				]
			)
	);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled p2sh ok';
};

subtest 'checking der_signatures' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(der_signatures => !!0);
	my $tx = btc_transaction->from_serialized([hex => $p2sh_p2wpkh]);

	# modify witness to make non-strict signature
	$tx->inputs->[0]->witness->[0] .= "\x01";

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled null_dummy ok';
};

subtest 'checking null_dummy' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(null_dummy => !!0);
	my $tx = btc_transaction->from_serialized([hex => $p2wsh_multisig]);

	# modify null_dummy element
	$tx->inputs->[0]->witness->[0] = "\x01";

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled null_dummy ok';
};

subtest 'checking checklocktimeverify' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(checklocktimeverify => !!0);

	# OP_CHECKLOCKTIMEVERIFY marks script as invalid on negative number
	my $tx = build_tx(
		btc_script->new
			->add('OP_CHECKLOCKTIMEVERIFY')
			->add('OP_1'),
		btc_script->new
			->push_number(-1),
	);

	ok dies { $tx->verify }, 'checking with all flags ok';
	ok lives { $tx->verify(flags => $flags) }, 'checking with disabled checklocktimeverify ok';
};

subtest 'checking checksequenceverify' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(checksequenceverify => !!0);

	# OP_CHECKSEQUENCEVERIFY marks script as invalid on negative number
	my $tx = build_tx(
		btc_script->new
			->add('OP_CHECKSEQUENCEVERIFY')
			->add('OP_1'),
		btc_script->new
			->push_number(-1),
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

################################
### STANDARDNESS FLAG CHECKS ###
################################

subtest 'checking signature_pushes_only' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(signature_pushes_only => !!1);

	my $tx = build_tx(
		btc_script->new
			->push_number(1)
			->add('OP_NUMEQUAL'),
		btc_script->new
			->push_number(0)
			->add('OP_DROP')
			->push_number(1),
	);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking minimal_if' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(minimal_if => !!1);

	my $script = btc_script->new
		->add('OP_IF')
		->push_number(1)
		->add('OP_ELSE')
		->push_number(0)
		->add('OP_ENDIF');

	my $tx = build_tx(
		$script->witness_program,
		undef,
		[
			"\x02",
			$script->to_serialized,
		],
	);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking compressed_pubkeys' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(compressed_pubkeys => !!1);

	$privkey->set_compressed(!!0);

	my $script = btc_script->new
		->push($privkey->get_public_key->to_serialized)
		->add('OP_CHECKSIG');

	my $tx = build_tx(
		$script->witness_program,
	);

	$tx->sign(signing_index => 0, script => $script)
		->add_signature($privkey)
		->finalize;

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking strict_encoding' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(strict_encoding => !!1);

	# uncompressed public key, but replace 04 with 06, which is not strict
	my $pubkey = $privkey->get_public_key->to_serialized;
	substr $pubkey, 0, 1, "\x06";

	my $script = btc_script->new
		->push($pubkey)
		->add('OP_CHECKSIG');

	my $tx = build_tx(
		$script
	);

	my $digest = $tx->get_digest(
		signing_index => 0,
		signing_subscript => $script->to_serialized,
	);

	# need to sign manually, because signer checks if pubkeys match
	$tx->inputs->[0]->signature_script
		->push($privkey->sign_message($digest) . chr SIGHASH_ALL);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

# clear compression flag
$privkey->set_compressed(!!1);

subtest 'checking low_s_signatures' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(low_s_signatures => !!1);
	my $tx = btc_transaction->from_serialized([hex => $p2pk_low_s_sig]);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking minimal_data' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(minimal_data => !!1);

	# construct a non-minimal push by hand
	my $tx = build_tx(
		btc_script->new
			->push_number(1),
		btc_script->new
			->add('OP_PUSHDATA1')
			->push([hex => '0bad']),
	);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking null_fail' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(null_fail => !!1);

	# bogus signature
	my $tx = build_tx(
		btc_script->new
			->push($privkey->get_public_key->to_serialized)
			->add('OP_CHECKSIG')
			->add('OP_1'),
		btc_script->new
			->push([hex => '0bad']),
	);

	# need to also disable der_signatures
	ok lives { $tx->verify(flags => {der_signatures => !!0}) }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking clean_stack' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(clean_stack => !!1);

	# bogus signature
	my $tx = build_tx(
		btc_script->new
			->add('OP_1'),
		btc_script->new
			->push([hex => '0bad']),
	);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking const_script' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(const_script => !!1);

	my $tx = build_tx(
		btc_script->new
			->add('OP_CODESEPARATOR')
			->push($privkey->get_public_key->to_serialized)
			->add('OP_CHECKSIG'),
	);

	$tx->sign(signing_index => 0)
		->add_signature($privkey)
		->finalize;

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking known_witness' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new(known_witness => !!1);

	my $tx = build_tx(
		btc_script->new
			->push_number(16)
			->push([hex => '0bad']),
	);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

subtest 'checking illegal_upgradeable_nops' => sub {
	my $flags = Bitcoin::Crypto::Transaction::Flags->new_empty(illegal_upgradeable_nops => !!1);

	my $tx = build_tx(
		btc_script->new
			->add('OP_NOP10')
			->push_number(1),
	);

	ok lives { $tx->verify }, 'checking with consensus flags ok';
	ok dies { $tx->verify(flags => $flags) }, 'checking with test flag ok';
};

done_testing;

sub build_tx
{
	my ($locking, $signature, $witness) = @_;

	my $utxo = btc_utxo->new(
		txid => "\x01" x 32,
		output_index => 0,
		output => {
			locking_script => $locking,
			value => 500,
		}
	);

	my $tx = btc_transaction->new;

	$tx->add_input(
		utxo => $utxo,
		(defined $signature ? (signature_script => $signature) : ()),
		(defined $witness ? (witness => $witness) : ()),
	);

	$tx->add_output(
		locking_script => "\x01",
		value => 500,
	);

	return $tx;
}

