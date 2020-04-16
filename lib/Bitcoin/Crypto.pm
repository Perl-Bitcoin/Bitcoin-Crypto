package Bitcoin::Crypto;

our $VERSION = "0.994";

use Modern::Perl "2010";
use Exporter qw(import);

our @EXPORT_OK = qw(btc_extprv btc_prv btc_extpub btc_pub btc_script);
our %EXPORT_TAGS = (all => [@EXPORT_OK]);

sub btc_extprv
{
	my $package = "Bitcoin::Crypto::Key::ExtPrivate";
	eval "require $package";
	return $package;
}

sub btc_prv
{
	my $package = "Bitcoin::Crypto::Key::Private";
	eval "require $package";
	return $package;
}

sub btc_extpub
{
	my $package = "Bitcoin::Crypto::Key::ExtPublic";
	eval "require $package";
	return $package;
}

sub btc_pub
{
	my $package = "Bitcoin::Crypto::Key::Public";
	eval "require $package";
	return $package;
}

sub btc_script
{
	my $package = "Bitcoin::Crypto::Script";
	eval "require $package";
	return $package;
}

__END__
=head1 NAME

Bitcoin::Crypto - Bitcoin cryptography in Perl

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::ExtPrivate;

	# extended keys are used for mnemonic generation and key derivation
	my $mnemonic = Bitcoin::Crypto::Key::ExtPrivate->generate_mnemonic();
	say "your mnemonic code is: $mnemonic";

	my $master_key = Bitcoin::Crypto::Key::ExtPrivate->from_mnemonic($mnemonic);
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

Cryptographic package for common Bitcoin-related tasks and key pair management.

=head1 SCOPE

This package allows you to do basic tasks for Bitcoin such as:

=over 2

=item * creating extended keys and utilising bip32 key derivation

=item * creating private key / public key pairs

=item * creating Bitcoin addresses

=item * creating signatures for messages

=item * importing / exporting using popular mediums (WIF, mnemonic, hex)

=item * using custom (non-Bitcoin) networks

=back

This package won't help you with:

=over 2

=item * serializing transactions

=item * using any Bitcoin CLI tools / clients

=item * connecting to Bitcoin network

=back

See child modules for more documentation and examples.

=head1 SHORTCUT FUNCTIONS

This package exports the following function when asked for them. They are shourtcut functions and will load needed packages and return their names. You can then use names of loaded packages to instantiate them however you want. You can also load all of them with the I<:all> tag in import.

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

Although the module was written with an extra care and appropriate tests are in place asserting compatibility with many Bitcoin standards, due to complexity of the subject some bugs may still be present. In the world of digital money, a single bug may lead to losing funds. I encourage anyone to test the module themselves, review the test cases and use the module with care, espetially in the beta phase. Suggestions for improvements and more edge cases to test will be gladly accepted, but there is no warranty on your funds being manipulated by this module.

=head1 INSTALLATION

This module requires development GMP package installed on your system. It must be installed before installing other dependencies.

For the best performance during dependencies installation ensure that you have Math::BigInt::GMP package installed. Some of the dependencies can run their test suites orders of magnitude faster with GMP available.

=head1 TODO

=over 2

=item * Bitcoin script execution (maybe?)

=item * Better test coverage

=back

=head1 AUTHOR

Bartosz Jarzyna E<lt>brtastic.dev@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2018 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
