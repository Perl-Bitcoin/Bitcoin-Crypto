use v5.10;
use strict;
use warnings;
use Test::More;

use Bitcoin::Crypto qw(btc_script);

my @cases = (
	[
		'P2PK',
		[
			hex =>
				'410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac'
		]
	],

	[
		'P2PK',
		[hex => '2102394fde5115357067c1d728210fc43aa1573ed52522b6f6d560fe29f1d0d1967cac']
	],

	[
		'P2PKH',
		[hex => '76a9142099fe62b65c69928ffef486987f8216fd68f9c488ac']
	],

	[
		'P2SH',
		[hex => 'a9149a8f9842b219cf5a54dfd389593b6a3dfe838a2687']
	],

	[
		'P2WPKH',
		[hex => '00145f011e3cfa337698e7fe4502143eb6ada0b5a3d1']
	],

	[
		'P2WSH',
		[hex => '0020e5c7c00d174631d2d1e365d6347b016fb87b6a0c08902d8e443989cb771fa7ec']
	],

	[
		undef,
		[
			hex =>
				'5121037953dbf08030f67352134992643d033417eaa6fcfb770c038f364ff40d7615882100b19937932727f9c58a151bff532475994751133f233ca80bab6fa80a1aa6e2b452ae'
		]
	],
);

my $case_num = 0;
foreach my $case (@cases) {
	my ($type, $raw_script) = @$case;
	my $type_str = $type // 'no type';

	subtest "testing script type guessing for case $case_num ($type_str)" => sub {
		my $script = btc_script->from_serialized($raw_script);

		my $got_type = $script->type // 'no type';
		is $got_type, $type_str, 'type ok';
		is !!$script->has_type, !!$type, 'has_type ok';
	};

	++$case_num;
}

done_testing;

