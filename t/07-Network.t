use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok 'Bitcoin::Crypto::Network' }

subtest 'registering invalid network fails' => sub {
	my $starting_count = scalar Bitcoin::Crypto::Network->find;

	my $litecoin = {
		id => 'litecoin',
		name => 'Litecoin Mainnet',
		p2pkh_byte => "\x30",
	};

	dies_ok {
		Bitcoin::Crypto::Network->register(%$litecoin);
	} 'invalid network validation fails';

	cmp_ok(
		Bitcoin::Crypto::Network->find, '==', $starting_count,
		'network list unchanged'
	);
};

subtest 'registering valid network succeeds' => sub {
	my $litecoin = {
		id => 'litecoin',
		name => 'Litecoin Mainnet',
		p2pkh_byte => "\x30",
		wif_byte => "\xb0",
	};

	lives_and {
		$litecoin = Bitcoin::Crypto::Network->register(%$litecoin);
		isa_ok $litecoin, 'Bitcoin::Crypto::Network';
		is(Bitcoin::Crypto::Network->get($litecoin->id)->id, $litecoin->id);
	} 'network validates and gets registered';
};

subtest 'setting default network works' => sub {
	my $litecoin = Bitcoin::Crypto::Network->get('litecoin');
	$litecoin->set_default;

	is(
		Bitcoin::Crypto::Network->get->id, $litecoin->id,
		'network successfully flagged as default'
	);
};

subtest 'finding a network works' => sub {
	my $litecoin = Bitcoin::Crypto::Network->get('litecoin');

	is_deeply [Bitcoin::Crypto::Network->find(sub { shift->wif_byte eq "\xb0" })], [$litecoin->id],
		'network found successfully';
	ok !Bitcoin::Crypto::Network->find(sub { shift->name eq 'unexistent' }),
		'non-existent network not found';
};

done_testing;

