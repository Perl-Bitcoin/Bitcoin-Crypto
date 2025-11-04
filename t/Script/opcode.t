use Test2::V0;
use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Tapscript;

subtest 'testing opcode_class' => sub {
	is(Bitcoin::Crypto::Script->opcode_class, 'Bitcoin::Crypto::Script::Opcode', 'script class ok');
	is(Bitcoin::Crypto::Tapscript->opcode_class, 'Bitcoin::Crypto::Tapscript::Opcode', 'tapscript class ok');
};

subtest 'testing getting OP_TRUE' => sub {
	my $script_op = Bitcoin::Crypto::Script->opcode_class->get_opcode_by_name('OP_TRUE');
	isa_ok $script_op, 'Bitcoin::Crypto::Script::Opcode';
	is $script_op->name, 'OP_TRUE', 'script opcode name ok';

	my $tapscript_op = Bitcoin::Crypto::Tapscript->opcode_class->get_opcode_by_name('OP_TRUE');
	isa_ok $tapscript_op, 'Bitcoin::Crypto::Tapscript::Opcode';
	is $tapscript_op->name, 'OP_TRUE', 'opcode name ok';
};

subtest 'testing getting opcode 187' => sub {
	my $script_op = Bitcoin::Crypto::Script->opcode_class->get_opcode_by_code(187);
	isa_ok $script_op, 'Bitcoin::Crypto::Script::Opcode';
	is $script_op->name, 'UNKNOWN', 'script opcode name ok';
	is $script_op->code, 187, 'script opcode code ok';

	my $tapscript_op = Bitcoin::Crypto::Tapscript->opcode_class->get_opcode_by_code(187);
	isa_ok $tapscript_op, 'Bitcoin::Crypto::Tapscript::Opcode';
	is $tapscript_op->name, 'OP_SUCCESS187', 'opcode name ok';
};

subtest 'testing getting tapscript opcode 0xba' => sub {
	my $tapscript_op = Bitcoin::Crypto::Tapscript->opcode_class->get_opcode_by_code(0xba);
	isa_ok $tapscript_op, 'Bitcoin::Crypto::Tapscript::Opcode';
	is $tapscript_op->name, 'OP_CHECKSIGADD', 'opcode name ok';
};

done_testing;

