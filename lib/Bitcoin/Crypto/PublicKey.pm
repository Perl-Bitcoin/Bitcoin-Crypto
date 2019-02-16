package Bitcoin::Crypto::PublicKey;

use Modern::Perl "2010";
use Moo;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Digest::SHA qw(sha256);
use Carp qw(croak);

use Bitcoin::Crypto::Base58 qw(encode_base58check);

with "Bitcoin::Crypto::Roles::BasicKey";

sub _isPrivate { 0 }

sub getAddress
{
    my ($self) = @_;
    my $pubkey = $self->toBytes();
    my $pkh = pack("C", $self->network->{p2pkh_byte}) . ripemd160(sha256($pubkey));
    return encode_base58check($pkh);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::PublicKey - class for Bitcoin public keys

=head1 SYNOPSIS

  use Bitcoin::Crypto::PublicKey;

  # verify signature (it has to be byte string, see perlpacktut)

  $pub->verifyMessage("Hello world", $sig);

  # getting address from public key (p2pkh)

  my $address = $pub->getAddress();

=head1 DESCRIPTION

This class allows you to create a public key instance.

You can use a public key to:

=over 2

=item * read from and export to byte / hexadecimal string

=item * verify messages

=item * create p2pkh address

=back

This class doesn't:

=over 2

=item * create any addresses other than p2pkh (yet)

=back

=head1 METHODS

=head2 fromHex($str) / fromBytes($str)

Use these methods to create a PublicKey instance.
All take single string argument with public key data.
Returns class instance.

=head2 new($instance)

Takes a single argument which must be instance of L<Crypt::PK::ECC>.
This allows you to use raw Crypt::PK::ECC methods to create key on your own.

=head2 setCompressed($val)

Change key's compression state to $val (1/0). This will change the Address generated
by public key. If $val is omitted it is set to 1.
Returns current key instance.

=head2 setNetwork($val)

Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. This will
enable generation of this network's addresses.
Returns current key instance.

=head2 getAddress()

Returns string containing Base58Check encoded public key hash (p2pkh address)

=head2 verifyMessage($message, $signature, $algo)

Verifies $signature against digest of $message (with $algo digest algorithm)
using public key.
$algo must be available in Digest package.
Returns boolean.

=head2 toHex() / toBytes()

Returns public key representation in specified format.

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::PrivateKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut
