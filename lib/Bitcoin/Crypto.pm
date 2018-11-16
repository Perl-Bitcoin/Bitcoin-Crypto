package Bitcoin::Crypto;

our $VERSION = "0.01";

use Modern::Perl "2010";
use Exporter qw(import);

our @EXPORT_OK = qw(version);

sub version
{
    return $VERSION;
}

__END__
=head1 NAME

Bitcoin::Crypto - Bitcoin cryptography in Perl

=head1 SYNOPSIS

  use Bitcoin::Crypto::PrivateKey;

  my $priv = Bitcoin::Crypto::PrivateKey->fromWif($wif_string);
  my $pub = $priv->getPublicKey();

  say "public key: " . $pub->toHex();
  say "address: " . $pub->getAddress();

  my $message = "Hello CPAN";
  my $signature = $priv->signMessage($message);

  if ($pub->verifyMessage($message, $signature)) {
      say "successfully signed message '$message'";
      say "signature: " . unpack "H*", $signature;
  }

=head1 DESCRIPTION

This package allows you to do basic cryptography tasks for Bitcoin such as:

=over 2

=item * creating private key / public key pairs

=item * creating Bitcoin addresses (p2pkh)

=item * creating signatures for messages

=item * importing / exporting using popular mediums (WIF, mnemonic, hex)

=item * creating custom (non-Bitcoin) networks

=back

This package won't help you with:

=over 2

=item * generating random entropy for private keys

=item * serializing transactions

=item * using any Bitcoin CLI tools / clients

=item * connecting to Bitcoin network

=back

See child modules for more documentation and examples.

=head1 TODO

=over 2

=item * P2SH addresses

=item * Bech32 addresses

=item * Extended private keys, key deriviation

=back

=head1 SEE ALSO

=over 2

=item Bitcoin::Crypto::PrivateKey

=item Bitcoin::Crypto::PublicKey

=item Bitcoin::Crypto::Network

=back

=head1 AUTHOR

Bartosz Jarzyna E<lt>brtastic.dev@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2018 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
