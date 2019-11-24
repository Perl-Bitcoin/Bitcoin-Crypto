use strict;
use warnings;

use Test::More;

BEGIN { use_ok('Bitcoin::Crypto::Script') };

my %data = (
	"00" => sub {
		shift
			->push_bytes("\x00");
	},
	"4c4c" . "01" x 76 => sub {
		shift
			->push_bytes("\x01" x 76);
	},
	"51609301119c" => sub {
		shift
			->add_operation("OP_1")
			->add_operation("OP_16")
			->add_operation("OP_ADD")
			->push_bytes("\x11")
			->add_operation("OP_NUMEQUAL");
	},
);

while (my ($expected, $sub) = each %data) {
	my $script = new Bitcoin::Crypto::Script;
	$sub->($script);
	is(lc unpack("H*", $script->get_script), $expected, "script created correctly");
}

done_testing;
