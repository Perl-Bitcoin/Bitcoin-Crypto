use strict;
use warnings;

use Test::More;

BEGIN { use_ok('Bitcoin::Crypto::Script') };

my $script = new Bitcoin::Crypto::Script;

$script
	->add_operation("OP_1")
	->add_operation("OP_16")
	->add_operation("OP_ADD")
	->push_bytes("\x11")
	->add_operation("OP_NUMEQUAL");

my $script_expected = unpack "H*", "\x51\x60\x93\x01\x11\x9c";
is(unpack("H*", $script->get_script), $script_expected, "script created correctly");

done_testing;
