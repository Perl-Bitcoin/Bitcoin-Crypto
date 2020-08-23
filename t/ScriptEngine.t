use v5.10; use warnings;
use Test::More;
use Bitcoin::Crypto;
use Bitcoin::Crypto::Script;

BEGIN { use_ok('Bitcoin::Crypto::ScriptEngine') }

is(Bitcoin::Crypto::ScriptEngine->VERSION, Bitcoin::Crypto->VERSION);

my $tonum = \&Bitcoin::Crypto::ScriptEngine::to_script_number;
my $fromnum = \&Bitcoin::Crypto::ScriptEngine::from_script_number;

NUMBER_ENCODING: {
	is $tonum->(1), "\x01";
	is $tonum->(0), "\x00";
	is $tonum->(-1), "\x81";
	is $tonum->(-128), "\x80\x80";
	is $tonum->(65535), "\xFF\xFF\x00";

	foreach my $num (-1000, -254, -127, 0, 127, 128, 65536) {
		is $fromnum->($tonum->($num)), $num, "number encoding / decoding ok";
	}
}

sub test_stack
{
	my ($stack, $expected) = @_;

	ok @$stack == 1, "stack size after execution ok";
	is $fromnum->(shift @$stack), $expected, "execution result ok";
}

test_stack(Bitcoin::Crypto::Script
	->new
	->push_number(15)
	->push_number(5)
	->add_operation("OP_ADD")
	->execute, 20);


test_stack(Bitcoin::Crypto::Script
	->new
	->push_number(7)
	->add_operation("OP_NEGATE")
	->execute, -7);

done_testing;
