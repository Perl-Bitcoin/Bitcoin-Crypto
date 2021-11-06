package Bitcoin::Crypto;

our $VERSION = "1.005";

use v5.10;
use strict;
use warnings;
use Exporter qw(import);

our @EXPORT_OK = qw(btc_extprv btc_prv btc_extpub btc_pub btc_script);
our %EXPORT_TAGS = (all => [@EXPORT_OK]);

sub btc_extprv
{
	require Bitcoin::Crypto::Key::ExtPrivate;
	return "Bitcoin::Crypto::Key::ExtPrivate";
}

sub btc_prv
{
	require Bitcoin::Crypto::Key::Private;
	return "Bitcoin::Crypto::Key::Private";
}

sub btc_extpub
{
	require Bitcoin::Crypto::Key::ExtPublic;
	return "Bitcoin::Crypto::Key::ExtPublic";
}

sub btc_pub
{
	require Bitcoin::Crypto::Key::Public;
	return "Bitcoin::Crypto::Key::Public";
}

sub btc_script
{
	require Bitcoin::Crypto::Script;
	return "Bitcoin::Crypto::Script";
}

__END__
=head1 NAME

Bitcoin::Crypto - Bitcoin cryptography in Perl

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_extprv);

	# extended keys are used for mnemonic generation and key derivation
	my $mnemonic = btc_extprv->generate_mnemonic();
	say "your mnemonic code is: $mnemonic";

	my $master_key = btc_extprv->from_mnemonic($mnemonic);
	my $derived_key = $master_key->derive_key("m/0'");

	# basic keys are used for signatures and addresses
	my $priv = $derived_key->get_basic_key();
	my $pub = $priv->get_public_key();

	say "private key: " . $priv->to_wif();
	say "public key: " . $pub->to_hex();
	say "address: " . $pub->get_segwit_address();

	my $message = "Hello CPAN";
	my $signature = $priv->sign_message($message);

	if ($pub->verify_message($message, $signature)) {
		say "successfully signed message '$message'";
		say "signature: " . unpack "H*", $signature;
	}

=head1 DESCRIPTION

Cryptographic module for common Bitcoin-related tasks and key pair management.

=head1 SCOPE

This module allows you to do basic tasks for Bitcoin such as:

=over 2

=item * creating extended keys and utilizing bip32 key derivation

=item * creating private key / public key pairs

=item * address generation (in legacy, compatibility and segwit formats)

=item * signature generation and verification

=item * importing / exporting using popular mediums (WIF, mnemonic, hex)

=item * using custom (non-Bitcoin) networks

=back

This module won't help you with:

=over 2

=item * serializing transactions

=item * using any Bitcoin CLI tools / clients

=item * connecting to Bitcoin network

=back

=head1 WHERE TO START?

Documentation and examples in this module assume you're already familiar with the basics of Bitcoin protocol and asymmetric cryptography. If that's not the case, start with learning about those topics.

If you like to learn by example, dive right into the examples directory.

There are many things that you may want to achieve with this module. Common topics include:

=over 2

=item * create a key pair for signature or address generation

Start with L<Bitcoin::Crypto::Key::Private> if you already have some data you want to use as a private key entropy (like Bitcoin's WIF format or hex data). If you'd like to generate a key and get a list of words (a mnemonic), L<Bitcoin::Crypto::Key::ExtPrivate> is what you want.

=item * generate many keys at once

L<Bitcoin::Crypto::Key::ExtPrivate> will allow you to derive as many keys as you want from a master key, so you won't have to store multiple private key seeds. L<Bitcoin::Crypto::Key::ExtPublic> can be then used to derive public keys lazily. I<(Note: storing extended public keys together with private keys in a hot storage will put your extended private key at risk!)>

=item * work with other cryptocurrencies

You can work with any cryptocurrency as long as it is based on the same fundamentals as Bitcoin. You have to register a network in L<Bitcoin::Crypto::Network> first, with the protocol data valid for your cryptocurrency.

=item * serialize a Bitcoin script

L<Bitcoin::Crypto::Script> will help you build and serialize a script, but not run it.

=item * work with Bitcoin-related encodings

See L<Bitcoin::Crypto::Base58> and L<Bitcoin::Crypto::Bech32>.

=back

=head1 HOW TO READ THE DOCUMENTATION?

Most functions in this documentation have a code line showcasing the arguments used by the function.

These lines are not meant to be valid perl. They're there for you to understand what arguments the function expects.

Most packages in this module have the types of their thrown exceptions documented near the bottom of the document. The exceptions section may be useful to understand which types of exceptions can be thrown when using functions or methods from the package and what they mean. It is not meant to be a full list of exceptions a function can throw and unblessed errors may still be raised.

=head1 SHORTCUT FUNCTIONS

This package exports the following functions when asked for them. They are shourtcut functions and will load needed packages and return their names. You can then use names of loaded packages to instantiate them however you want. You can also load all of them with the I<:all> tag in import. These functions can be used as follows:

	use Bitcoin::Crypto qw(btc_pub);

	# loads Bitcoin::Crypto::Key::Public and returns package name
	# we can now use it to run its methods
	my $public_key = btc_pub->from_hex($hex_data);

=head2 btc_extprv

Loads L<Bitcoin::Crypto::Key::ExtPrivate>

=head2 btc_prv

Loads L<Bitcoin::Crypto::Key::Private>

=head2 btc_extpub

Loads L<Bitcoin::Crypto::Key::ExtPublic>

=head2 btc_pub

Loads L<Bitcoin::Crypto::Key::Public>

=head2 btc_script

Loads L<Bitcoin::Crypto::Script>

=head1 DISCLAIMER

Although the module was written with an extra care and appropriate tests are in place asserting compatibility with many Bitcoin standards, due to complexity of the subject some bugs may still be present. In the world of digital money, a single bug may lead to losing funds. I encourage anyone to test the module themselves, review the test cases and use the module with care. Suggestions for improvements and more edge cases to test will be gladly accepted, but there is no warranty on your funds being manipulated by this module.

=head1 SPEED

Since most of the calculations are delegated to the XS (and further to libtommath and libtomcrypt) most tasks should be fairly quick to finish, in Perl definition of quick.
The module have a little bit of startup time because of Moo and Type::Tiny, measured in miliseconds. The biggest runtime bottleneck seem to be the key derivation mechanism, which imports a key once for every derivation path part. Some tasks, like signature generation and verification, should be very fast thanks to libtomcrypt doing all the heavy lifting. All in all, the module should be able to handle any task which does not require brute forcing (like vanity address generation).

=head1 TODO

=over 2

=item * Taproot compatibility

=item * Better test coverage

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::RPC::Client>

=item L<https://github.com/bitcoin/bips>

=back

=head1 AUTHOR

Bartosz Jarzyna E<lt>brtastic.dev@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2018 - 2021 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
