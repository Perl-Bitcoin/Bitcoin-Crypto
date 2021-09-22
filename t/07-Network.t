use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok 'Bitcoin::Crypto::Network' }

# default networks

my %default_mapped = map { $_ => 1 } Bitcoin::Crypto::Network->find;
my $count = scalar keys %default_mapped;
ok defined $default_mapped{bitcoin},
	"mainnet available";
ok defined $default_mapped{bitcoin_testnet},
	"testnet available";

my $litecoin = {
	id => "litecoin",
	name => "Litecoin Mainnet",
	p2pkh_byte => "\x30",
};

# network validation

dies_ok {
	Bitcoin::Crypto::Network->register(%$litecoin);
}
"invalid network validation fails";

cmp_ok(
	Bitcoin::Crypto::Network->find, "==", $count,
	"network list unchanged"
);

$litecoin->{wif_byte} = "\xb0";

lives_and {
	$litecoin = Bitcoin::Crypto::Network->register(%$litecoin);
	isa_ok $litecoin, "Bitcoin::Crypto::Network";
	is(Bitcoin::Crypto::Network->get($litecoin->id)->id, $litecoin->id);
}
"network validates and gets registered";

# default network

$litecoin->set_default;
is(
	Bitcoin::Crypto::Network->get->id, $litecoin->id,
	"network successfully flagged as default"
);

# finding the network

is_deeply [Bitcoin::Crypto::Network->find(sub { shift->wif_byte eq "\xb0" })], [$litecoin->id],
	"network found successfully";
ok !Bitcoin::Crypto::Network->find(sub { shift->name eq "unexistent" }),
	"non-existent network not found";

done_testing;
