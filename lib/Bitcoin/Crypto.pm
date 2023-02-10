package Bitcoin::Crypto;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);

our @EXPORT_OK = qw(btc_extprv btc_prv btc_extpub btc_pub btc_script);
our %EXPORT_TAGS = (all => [@EXPORT_OK]);

sub btc_extprv
{
	require Bitcoin::Crypto::Key::ExtPrivate;
	return 'Bitcoin::Crypto::Key::ExtPrivate';
}

sub btc_prv
{
	require Bitcoin::Crypto::Key::Private;
	return 'Bitcoin::Crypto::Key::Private';
}

sub btc_extpub
{
	require Bitcoin::Crypto::Key::ExtPublic;
	return 'Bitcoin::Crypto::Key::ExtPublic';
}

sub btc_pub
{
	require Bitcoin::Crypto::Key::Public;
	return 'Bitcoin::Crypto::Key::Public';
}

sub btc_script
{
	require Bitcoin::Crypto::Script;
	return 'Bitcoin::Crypto::Script';
}

__END__

=head1 NAME

Bitcoin::Crypto - Bitcoin cryptography in Perl

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_extprv);
	use Bitcoin::Crypto::Util qw(generate_mnemonic to_format);

	# extended keys are used for mnemonic generation and key derivation
	my $mnemonic = generate_mnemonic;
	say "your mnemonic code is: $mnemonic";

	my $master_key = btc_extprv->from_mnemonic($mnemonic);
	my $derived_key = $master_key->derive_key("m/0'");

	# basic keys are used for signatures and addresses
	my $priv = $derived_key->get_basic_key;
	my $pub = $priv->get_public_key;

	say 'private key: ' . $priv->to_wif;
	say 'public key: ' . to_format [hex => $pub->to_str];
	say 'address: ' . $pub->get_segwit_address;

	my $message = 'Hello CPAN';
	my $signature = $priv->sign_message($message);

	if ($pub->verify_message($message, $signature)) {
		say "successfully signed message '$message'";
		say 'signature: ' . to_format [hex => $signature];
	}

=head1 DESCRIPTION

Cryptographic module for common Bitcoin-related tasks.

=head1 SCOPE

This module allows you to perform low-level tasks for Bitcoin such as:

=over

=item * creating extended keys and utilizing bip32 key derivation

=item * creating private key / public key pairs

=item * building, serializing and running transaction scripts

=item * address generation (in legacy, compatibility and segwit formats)

=item * signature generation and verification

=item * importing / exporting using popular mediums (WIF, mnemonic, hex)

=item * using custom (non-Bitcoin) networks

=back

This module won't help you with:

=over

=item * serializing transactions

=item * using any Bitcoin CLI tools / clients

=item * connecting to Bitcoin network

=back

=head1 WHERE TO START?

Documentation and examples in this module assume you're already familiar with
the basics of Bitcoin protocol and asymmetric cryptography. If that's not the
case, start with reading about those topics.

If you like to learn by example, dive right into the examples directory.

There are many goals which you may want to achieve with this module. Common
topics include:

=over

=item * create a key pair for signature or address generation

Start with L<Bitcoin::Crypto::Key::Private> if you already have some data you
want to use as a private key entropy (like Bitcoin's C<WIF> format or hex
data). If you'd like to generate list of words (a mnemonic) instead, see
L<Bitcoin::Crypto::Util/generate_mnemonic> and
L<Bitcoin::Crypto::Key::ExtPrivate/from_mnemonic>.

=item * generate many keys at once

L<Bitcoin::Crypto::Key::ExtPrivate> allows you to derive multiple keys from a
master key, so you don't have to store multiple private keys.
L<Bitcoin::Crypto::Key::ExtPublic> can be then used to derive public keys
lazily. I<(Note: storing extended public keys together with private keys in a
hot storage will put your extended private key at risk!)>

=item * work with other cryptocurrencies

You can work with any cryptocurrency as long as it is based on the same
fundamentals as Bitcoin. You have to register a network in
L<Bitcoin::Crypto::Network> first, with the protocol data valid for your
cryptocurrency.

=item * utilize Bitcoin Script

L<Bitcoin::Crypto::Script> will help you build, de/serialize and run a script.
L<Bitcoin::Crypto::Script::Runner> gives you more control over script execution,
including running the script step by step, stopping after each opcode.

=item * work with Bitcoin-related encodings

See L<Bitcoin::Crypto::Base58> and L<Bitcoin::Crypto::Bech32>.

=back

=head1 HOW TO READ THE DOCUMENTATION?

Most functions in this documentation have a code line showcasing the arguments
used by the function. These lines are not meant to be valid perl. They're there
for you to understand what arguments the function expects.

Most packages in this module have the types of their thrown exceptions
documented near the bottom of the document. The exceptions section may be
useful to understand which types of exceptions can be thrown when using
functions or methods from the package and what they mean. It is not meant to be
a full list of exceptions a function can throw and unblessed errors may still
be raised.

=head1 SHORTCUT FUNCTIONS

=head2 Exported interface

This package exports the following functions when asked for them. These are
shourtcut functions and will load needed packages and return their names. You
can then use names of loaded packages to instantiate them however you want. You
can also load all of them with the I<:all> tag in import. These functions can
be used as follows:

	use Bitcoin::Crypto qw(btc_pub);

	# loads Bitcoin::Crypto::Key::Public and returns package name
	# we can now use it to run its methods
	my $public_key = btc_pub->from_str([hex => $hex_data]);

=head3 btc_extprv

Loads L<Bitcoin::Crypto::Key::ExtPrivate>

=head3 btc_prv

Loads L<Bitcoin::Crypto::Key::Private>

=head3 btc_extpub

Loads L<Bitcoin::Crypto::Key::ExtPublic>

=head3 btc_pub

Loads L<Bitcoin::Crypto::Key::Public>

=head3 btc_script

Loads L<Bitcoin::Crypto::Script>

=head1 DISCLAIMER

Although the module was written with an extra care and appropriate tests are in
place asserting compatibility with many Bitcoin standards, due to complexity of
the subject some bugs may still be present. In the world of digital money, a
single bug may lead to losing funds. I encourage anyone to test the module
themselves, review the test cases and use the module with care. Suggestions for
improvements and more edge cases to test will be gladly accepted, but there is
no warranty on your funds being manipulated by this module.

=head1 TODO

I will gladly accept help working on these:

=over 2

=item * Taproot compatibility

=item * Better error checking (subroutine inputs, edge cases etc.)

=item * Detailed manual

=item * Better test coverage

=back

=head1 SEE ALSO

L<Bitcoin::RPC::Client>

L<https://github.com/bitcoin/bips>

=head1 AUTHOR

Bartosz Jarzyna E<lt>bbrtj.pro@gmail.comE<gt> (L<Support me|https://bbrtj.eu/support>)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2018 - 2023 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

