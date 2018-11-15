package Bitcoin::Crypto;

our $VERSION = "0.01";

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
- creating private key / public key pairs
- creating Bitcoin addresses (p2pkh)
- creating signatures for messages
- importing / exporting using popular mediums (WIF, mnemonic, hex)
- creating custom (non-Bitcoin) networks

This package won't help you with:
- generating random entropy for private keys
- serializing transactions
- using any Bitcoin CLI tools / clients
- connecting to Bitcoin network

See child modules for more documentation and examples.

=head1 TODO

- P2SH addresses
- Bech32 addresses
- Extended private keys, key deriviation

=head1 SEE ALSO

Bitcoin::Crypto::PrivateKey
Bitcoin::Crypto::PublicKey
Bitcoin::Crypto::Network

=head1 AUTHOR

Bartosz Jarzyna E<lt>brtastic.dev@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2018 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
