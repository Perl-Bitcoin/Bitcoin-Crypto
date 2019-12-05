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

my %addresses = (
	"52410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d4621353ae" => "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
);

while (my ($expected, $sub) = each %data) {
	my $script = new Bitcoin::Crypto::Script;
	$sub->($script);
	is(lc unpack("H*", $script->get_script), $expected, "script created correctly");
}

while (my ($scr, $address) = each %addresses) {
	my $script = new Bitcoin::Crypto::Script;
	$script->push_raw($scr);
	is($script->get_legacy_address(), $address, "address matches");
}

done_testing;
