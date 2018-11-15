package Bitcoin::Crypto::PublicKey;

use Modern::Perl "2010";
use Moo;
use Crypt::PK::ECC;
use Crypt::RIPEMD160;
use Try::Tiny;
use Digest::SHA qw(sha256);
use Carp qw(croak);

use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Config;

with "Bitcoin::Crypto::Roles::Key";

around BUILDARGS => sub {
    my ($orig, $class, $key) = @_;

    croak "Trying to create public key from private key data"
        if $key->is_private();

    return $class->$orig(keyInstance => $key);
};

sub fromBytes
{
    my ($class, $bytes) = @_;

    my $key = Crypt::PK::ECC->new();
    try {
        $key->import_key_raw($bytes, $config{curve_name});
    } catch {
        croak "Error creating key - check input data";
    };

    return $class->new($key);
}

sub getAddress
{
    my ($self) = @_;
    my $pubkey = $self->toBytes();
    my $pkh = pack("C", $self->network->{p2pkh_byte}) . Crypt::RIPEMD160->hash(sha256($pubkey));
    return encode_base58check($pkh);
}

sub rawKey
{
    my ($self) = @_;
    if ($self->compressed) {
        return $self->keyInstance->export_key_raw("public_compressed");
    } else {
        return $self->keyInstance->export_key_raw("public");
    }
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
- read from and export to byte / hexadecimal string
- verify messages
- create p2pkh address

This class doesn't:
- create any addresses other than p2pkh (yet)

=head1 METHODS

=head2 fromHex($str) / fromBytes($str)

Use these methods to create a PublicKey instance.
All take single string argument with public key data.
Returns class instance.

=head2 new($instance)

Takes a single argument which must be instance of Crypt::PK::ECC.
This allows you to use raw Crypt::PK::ECC methods to create key on your own.

=head2 setCompressed($val)

Change key's compression state to $val (1/0). This will change the Address generated
by public key.

=head2 setNetwork($val)

Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. This will
enable generation of this network's addresses.

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

Bitcoin::Crypto::PrivateKey
Bitcoin::Crypto::Network


=cut
