use Test2::V0;
use Bitcoin::Crypto qw(btc_script);

my @scripts_valid = (
	btc_script->new
		->add('OP_1')
		->add('OP_IF')
		->push_number(1)
		->add('OP_ELSE')
		->push_bytes("\xde\xad")
		->add('OP_ELSE')
		->push_bytes("\xbe\xef")
		->add('OP_ENDIF'),
);

my @scripts_invalid = (
	btc_script->new
		->add('OP_IF'),
	btc_script->new
		->add('OP_ELSE'),
	btc_script->new
		->add('OP_ENDIF'),
	btc_script->new
		->add('OP_VERIF'),
	btc_script->new
		->add('OP_VERNOTIF'),
	btc_script->new
		->add_raw("\x20")
		->add_raw('abcde'),
	btc_script->new
		->add('OP_PUSHDATA1'),
);

foreach my $ind (keys @scripts_valid) {
	my $script = $scripts_valid[$ind];

	subtest "sholud pass valid case $ind" => sub {
		ok lives { $script->assert_valid }, 'script valid ok';
		ok lives { $script->run }, 'script can be run ok';
		ok !$script->has_errors, 'erorrs ok';
		is ref $script->operations, 'ARRAY', 'can get script operations';
	};
}

foreach my $ind (keys @scripts_invalid) {
	my $script = $scripts_invalid[$ind];

	subtest "sholud pass invalid case $ind" => sub {
		ok dies { $script->assert_valid }, 'script valid ok';
		ok dies { $script->run }, 'script cant be run ok';
		ok $script->has_errors, 'erorrs ok';
		is ref $script->operations, 'ARRAY', 'can get script operations';
	};
}

done_testing;

