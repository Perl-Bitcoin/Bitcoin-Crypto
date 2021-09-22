use v5.10;
use strict;
use warnings;
use Test::More;
use Bitcoin::Crypto qw(btc_prv);

my $key = btc_prv->from_hex('b7331fd4ff8c53d31fa7d1625df7de451e55dc53337db64bee3efadb7fdd28d9');

my @messages = ("Perl test script", "", "a", "_ś\x1f " x 250);
for my $message (@messages) {
	my $signature = $key->sign_message($message);

	ok($key->sign_message($message) eq $signature, "Signatures generation should be deterministic")
		or diag('Make sure Crypt::Perl is installed');
	ok($key->verify_message($message, $signature), "Valid signature");
}

done_testing;
