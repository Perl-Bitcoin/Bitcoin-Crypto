use Modern::Perl "2010";
use Test::More;

BEGIN { use_ok('Bitcoin::Crypto::Script') };

my %data = (
	"00" => {
		"addresses" => [
			"3GENUmnERtWfQct4NegomUqqtZuzYGPwBS",
			"3B3pGhC2JDYAFd8827hZkY8GrmGfy82s9P",
			"bc1qdc6qh88lkdaf3899gnntk7q293ufq8flkvmnsa59zx3sv9a05qws6lzc42"
		],
		"script" => sub {
			shift
				->push_bytes("\x00");
		},
	},
	"4c4c" . "01" x 76 => {
		"addresses" => [
			"39ARnShZCXXCJNJ2nuFLPX9JQ94AwGu36X",
			"3Q5PDnAf4L4i694errLA1pKvoxK8KDXAAw",
			"bc1q49qt0x3xljjmpnh0w6g3urppu3fh6we7zlttmavz6h4rtazdxx2sw53d87"
		],
		"script" => sub {
			shift
				->push_bytes("\x01" x 76);
		},
	},
	"51609301119c" => {
		"addresses" => [
			"39PZSQJxFFGGVVP6AN7sYs8aGEdmxanjra",
			"3Gu9JcB3BGk3ma1jjSuNe6mz7JAQZ4uoeT",
			"bc1qmgr9c90faaeqlae2lqf9ncx7f6lvh3jrmcanmdhu6d4323dk8mnsytnzr4"
		],
		"script" => sub {
			shift
				->add_operation("OP_1")
				->add_operation("OP_16")
				->add_operation("OP_ADD")
				->push_bytes("\x11")
				->add_operation("OP_NUMEQUAL");
		},
	},
	"5121032b505cb176689d04c3c89590e46ac8bcac600ba3a45cc8a6f3dfcadea2e827b221024fad8c81793a1f2403fe9c8b1bbcdfe3bd2914b4419d182d5e91f0c343c9417052ae" => {
		"addresses" => [
			"36XHMXUu8hN2QiwPnn2ZUkdffeTRji3DnU",
			"3PTSFSe4ebrLzbUrFwzVdGEYjGa2gKCxep",
			"bc1q447s4tfl4xem9cvfrqql7jrhw9hp4z94yj0arhupkn0hgd3906lq46dzkf"
		],
		"script" => sub {
			shift
				->add_operation("OP_1")
				->push_bytes("\x03\x2b\x50\x5c\xb1\x76\x68\x9d\x04\xc3\xc8\x95\x90\xe4\x6a\xc8\xbc\xac\x60\x0b\xa3\xa4\x5c\xc8\xa6\xf3\xdf\xca\xde\xa2\xe8\x27\xb2")
				->push_bytes("\x02\x4f\xad\x8c\x81\x79\x3a\x1f\x24\x03\xfe\x9c\x8b\x1b\xbc\xdf\xe3\xbd\x29\x14\xb4\x41\x9d\x18\x2d\x5e\x91\xf0\xc3\x43\xc9\x41\x70")
				->add_operation("OP_2")
				->add_operation("OP_CHECKMULTISIG");
		},
	},
);

while (my ($expected, $info) = each %data) {
	my $script = Bitcoin::Crypto::Script->new;
	$info->{script}->($script);
	my ($addr_legacy, $addr_compat, $addr_segwit) = @{$info->{addresses}};
	is(lc unpack("H*", $script->get_script), $expected, "script created correctly");
	is($script->get_legacy_address, $addr_legacy, "legacy script address created correctly");
	is($script->get_compat_address, $addr_compat, "compat script address created correctly")
		if defined $addr_compat;
	is($script->get_segwit_address, $addr_segwit, "segwit script address created correctly")
		if defined $addr_segwit;
}

done_testing;
