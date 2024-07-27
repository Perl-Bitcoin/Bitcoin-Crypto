use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_extprv);
use Bitcoin::Crypto::BIP85;
use Getopt::Long;
use Pod::Usage;

my $words = 24;
my $index = 0;

GetOptions(
	'w|words=i' => \$words,
	'i|index=i' => \$index,
) or pod2usage(1);

my $extprv = btc_extprv->from_mnemonic(join(' ', @ARGV), undef, 'en');
my $generator = Bitcoin::Crypto::BIP85->new(
	key => $extprv,
);

say $generator->derive_mnemonic(words => $words, index => $index);

__END__

=head1 NAME

bip85_mnemonic - generate child mnemonics based on BIP85 spec

=head1 SYNOPSIS

	bip85_mnemonic [OPTIONS] MNEMONIC

=head1 OPTIONS

=head2 -w NUMBER, --words=NUMBER

The number of words to generate. 24 by default.

=head2 -i NUMBER, --index=NUMBER

The index to generate. 0 by default, increment to get different mnemonics.

=head1 DESCRIPTION

This program will derive child mnemonics from a parent mnemonic based on BIP39
application of BIP85 spec. It only accepts and generates English language mnemonics.

