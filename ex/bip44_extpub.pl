use v5.10;
use strict;
use warnings;

use Bitcoin::Crypto qw(btc_extprv btc_extpub);
use Bitcoin::Crypto::Constants;
use Getopt::Long;
use Pod::Usage;

my $generate = '';
my $count = 10;

GetOptions(
	'g|generate=s' => \$generate,
	'c|count=i' => \$count,
) or pod2usage(1);

my $extpub;
if ($generate) {
	my $purpose;
	$purpose = Bitcoin::Crypto::Constants::bip44_purpose
		if $generate eq 'legacy';
	$purpose = Bitcoin::Crypto::Constants::bip44_compat_purpose
		if $generate eq 'compat';
	$purpose = Bitcoin::Crypto::Constants::bip44_segwit_purpose
		if $generate eq 'segwit';

	die "unknown generate argument: $generate"
		if !$purpose;

	binmode STDIN, ':encoding(UTF-8)';

	my $mnemonic = readline STDIN;
	chomp $mnemonic;

	my $password = readline STDIN;
	chomp $password;

	my $extprv = btc_extprv->from_mnemonic($mnemonic, $password);
	my $derived = $extprv->derive_key_bip44(purpose => $purpose, get_account => 1);
	$extpub = $derived->get_public_key;

	say $extpub->to_serialized_base58;
}
else {
	$extpub = btc_extpub->from_serialized_base58(shift);
}

foreach my $i (0 .. $count - 1) {
	say "$i: " . $extpub->derive_key_bip44(index => $i)->get_basic_key->get_address;
}

__END__

=head1 NAME

bip44_extpub - generate extended public keys and addresses with bip44 derivation paths

=head1 SYNOPSIS

	bip44_extpub [OPTIONS] EXTPUB

=head1 OPTIONS

=head2 -g TYPE, --generate=TYPE

The program will wait for a mnemonic and a password, and then output an
extended public key before outputting the addresses.

C<EXTPUB> shouldn't be passed. The program will read two lines from STDIN
instead, so that mnemonic key isn't saved in bash history.

C<TYPE> should be either C<legacy>, C<compat> or C<segwit>.

=head2 -c COUNT, --count=COUNT

Will generate C<COUNT> addresses for given extpub (default 10)

=head1 DESCRIPTION

This program will help you generate addresses for your cold wallet while
keeping it safe. Use it to obtain an extended public key of your account
(Bitcoin, account 0) using your mnemonic. You can then use it again with
previously generated extended public key to generate more addresses without
risking your mnemonic.

