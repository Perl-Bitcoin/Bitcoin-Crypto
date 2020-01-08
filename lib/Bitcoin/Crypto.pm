package Bitcoin::Crypto;

our $VERSION = "0.991";

use Modern::Perl "2010";

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

=head1 DISCLAIMER

Although the module was written with an extra care and appropriate tests are in place asserting compatibility with many Bitcoin standards, due to complexity of the subject some bugs may still be present. In the world of digital money, a single bug may lead to losing funds. I encourage anyone to test the module themselves, review the test cases and use the module with care, espetially in the beta phase. Suggestions for improvements and more edge cases to test will be gladly accepted, but there is no warranty on your funds being manipulated by this module.

=head1 TODO

=over 2

=item * Bitcoin script execution (maybe?)

=item * Better test coverage

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::BIP39>

=item The examples directory

=back

=head1 AUTHOR

Bartosz Jarzyna E<lt>brtastic.dev@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2018 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
