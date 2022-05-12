use v5.10;
use strict;
use warnings;
use Test::More;

use Bitcoin::Crypto::Network;

# TODO: test some key derivation, address generation and wif generation
my %should_be_present = (
	bitcoin => {},
	bitcoin_testnet => {},
	dogecoin => {},
	dogecoin_testnet => {},
);

my %default_mapped = map { $_ => 1 } Bitcoin::Crypto::Network->find;
my $count = scalar keys %default_mapped;

for my $network_id (keys %should_be_present) {
	ok defined $default_mapped{$network_id}, "$network_id available ok";
}

is scalar keys %default_mapped, scalar keys %should_be_present, 'network count ok';

done_testing;

