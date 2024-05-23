use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_transaction);

say 'please provide a serialized transaction (hexadecimal):';
my $tx_hex = <STDIN>;
chomp $tx_hex;

say btc_transaction->from_serialized([hex => $tx_hex])->dump;

__END__

=head1 Transaction dumper

A very simple script to dump serialized transactions. Does not pull UTXO data
from anywhere, so printed data is always incomplete.

