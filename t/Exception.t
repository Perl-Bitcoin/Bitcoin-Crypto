use Test2::V0;
use Bitcoin::Crypto::Exception;

subtest 'test exception throwing' => sub {
	isa_ok dies {
		Bitcoin::Crypto::Exception->raise('test_message');
	}, 'Bitcoin::Crypto::Exception';

	my $err = dies {
		Bitcoin::Crypto::Exception->throw('test_message');
	};

	isa_ok($err, 'Bitcoin::Crypto::Exception');
	is($err->message, 'test_message', 'message ok');
	like("$err", qr/test_message/, 'class stringified');
	note("$err");
};

subtest 'test exception raising' => sub {
	my $err = dies {
		Bitcoin::Crypto::Exception::KeyCreate->raise('message');
	};

	isa_ok($err, 'Bitcoin::Crypto::Exception::KeyCreate');
	note($err);
};

{

	package BuggyDestroy;

	sub new
	{
		return bless {}, __PACKAGE__;
	}

	sub DESTROY
	{
		eval { 1 };
	}
}

subtest 'test exception trapping' => sub {
	isa_ok dies {
		Bitcoin::Crypto::Exception->trap_into(
			sub { die 'test'; }
		);
	}, 'Bitcoin::Crypto::Exception';

	ok lives {
		is(
			Bitcoin::Crypto::Exception->trap_into(
				sub { 54321 }
			),
			54321
		);
	}, 'trapped return value ok';

	my $err = dies {
		Bitcoin::Crypto::Exception->trap_into(
			sub {
				my $var = BuggyDestroy->new;
				die 'test';
			}
		);
	};

	isa_ok($err, 'Bitcoin::Crypto::Exception');
	note($err);
};

done_testing;

