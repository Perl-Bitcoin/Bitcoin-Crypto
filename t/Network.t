use strict;
use warnings;

use Test::More;
use Try::Tiny;
use Scalar::Util qw(blessed);

BEGIN { use_ok('Bitcoin::Crypto::Network', qw(:all)) };

# get_available_networks - 2 tests

my @default_networks = sort { $a cmp $b } get_available_networks();
is($default_networks[0], "mainnet", "mainnet available");
is($default_networks[1], "testnet", "testnet available");
note("no more default networks") if @default_networks == 2;

my $litecoin = {
	name => "Litecoin Mainnet",
	p2pkh_byte => "\x30",
};

# validate_network - 2 test

try {
	validate_network($litecoin);
	fail("invalid network validation successfull");
} catch {
	my $ex = $_;
	if (blessed $ex && $ex->isa("Bitcoin::Crypto::Exception") && $ex->code eq "network_config") {
		pass("invalid network validation fails");
	} else {
		fail("unknown error during validation");
	}
};

$litecoin->{wif_byte} = "\xb0";

try {
	validate_network($litecoin);
	pass("network validates");
} catch {
	fail("unknown error during validation");
};

# add_network - 1 test

add_network(litecoin_mainnet => $litecoin);
is_deeply(get_network("litecoin_mainnet"), $litecoin, "network added successfully");

# set_default_network - 2 tests

set_default_network("litecoin_mainnet");
is_deeply(get_default_network(), $litecoin, "network successfully flagged as default");
is_deeply(get_network(), $litecoin, "get_network() shortcut working");

# find_network - 2 test

is_deeply([find_network(wif_byte => "\xb0")], [qw(litecoin_mainnet)], "network found successfully");
ok(find_network(name => "unexistent") == 0, "non-existent network not found");

done_testing;
