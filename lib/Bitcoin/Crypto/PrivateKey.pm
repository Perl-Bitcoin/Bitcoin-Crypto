package Bitcoin::Crypto::PrivateKey;

use Modern::Perl "2010";
use Moo;
use MooX::Types::MooseLike::Base qw(Str);
use Crypt::PK::ECC;
use Bitcoin::BIP39 qw(bip39_mnemonic_to_entropy entropy_to_bip39_mnemonic);
use Carp qw(croak);
use List::Util qw(first);

use Bitcoin::Crypto::PublicKey;
use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Network qw(find_network get_network);
use Bitcoin::Crypto::Util qw(validate_wif);

with "Bitcoin::Crypto::Roles::BasicKey";
with "Bitcoin::Crypto::Roles::Network";
with "Bitcoin::Crypto::Roles::Compress";

around BUILDARGS => sub {
    my ($orig, $class, $key) = @_;

    croak "Trying to create private key from unknown key data"
        unless $key->is_private();

    return $class->$orig(keyInstance => $key);
};

sub toWif
{
    my ($self) = @_;
    my $bytes = $self->toBytes();
    my $missing = $config{key_max_length} - length $bytes;
    my $wifdata = pack("Cx$missing", $self->network->{wif_byte}) . $bytes;
    $wifdata .= pack("C", $config{wif_compressed_byte}) if $self->compressed;
    return encode_base58check($wifdata);
}

sub fromWif
{
    my ($class, $wif, $network) = @_;
    return undef if !validate_wif($wif);

    my $decoded = decode_base58check($wif);
    my $private = substr $decoded, 1;

    my $compressed = 0;
    if (length($private) % $config{key_length_step} == 1) {
        chop $private;
        $compressed = 1;
    }

    my $wif_network_byte = unpack("C", $decoded);
    my @found_networks = find_network(wif_byte => $wif_network_byte);
    @found_networks = first { $_ eq $network } @found_networks if defined $network;

    croak "Found multiple networks possible for given WIF. Please specify with third argument"
        if @found_networks > 1;
    croak "Network name $network cannot be used for given WIF"
        if @found_networks == 0 && defined $network;
    croak "Couldn't find network for WIF byte $wif_network_byte"
        if @found_networks == 0;

    my $instance = $class->fromBytes($private);
    $instance->setCompressed($compressed);
    $instance->setNetwork(@found_networks);
    return $instance;
}


sub signMessage
{
    my ($self, $message, $algorithm) = @_;
    $algorithm //= "sha256";
    return $self->keyInstance->sign_message($message, $algorithm);
}

sub getPublicKey
{
    my ($self) = @_;
    my $raw_public = $self->keyInstance->export_key_raw("public");
    my $key = Crypt::PK::ECC->new();
    $key->import_key_raw($raw_public, $config{curve_name});

    my $public = Bitcoin::Crypto::PublicKey->new($key);
    $public->setCompressed($self->compressed);
    $public->setNetwork($self->network);
    return $public;
}

sub rawKey
{
    my ($self) = @_;
    return $self->keyInstance->export_key_raw("private");
}


1;

__END__
=head1 NAME

Bitcoin::Crypto::PrivateKey - class for Bitcoin private keys

=head1 SYNOPSIS

  use Bitcoin::Crypto::PrivateKey;

  # get Bitcoin::Crypto::PublicKey instance from private key

  my $pub = $priv->getPublicKey();

  # create signature using private key (sha256 of string byte representation)

  my $sig = $priv->signMessage("Hello world");

  # signature is returned as byte string
  # use unpack to get the representation you need

  my $sig_hex = unpack "H*", $sig;

  # signature verification

  $priv->verifyMessage("Hello world", $sig);
  $priv->verifyBytes($packed_data, $sig);

=head1 DESCRIPTION

This class allows you to create a private key instance.

You can use a private key to:

=over 2

=item * read from and export to popular formats

=item * generate public keys

=item * sign and verify messages

=back

This class doesn't:

=over 2

=item * generate entropy for a private key

=item * derive private keys from a master key

=back

After creating an instance private key entropy will be prepended by some
NULL bytes if needed, for example if your entropy is 19 bytes long one extra
NULL byte will be added so that it is 20 bytes long. Minimum byte
size is 16, maximum is 32 and the step is 4 bytes. This allows creation of
mnemonics of standard word counts: 12, 15, 18, 21, 24.

Please note that any keys generated are by default compressed.

see L<Bitcoin::Crypto::Network> if you want to work with other networks than Bitcoin Mainnet.

=head1 METHODS

=head2 fromHex($str) / fromBytes($str) / fromBip39Mnemonic($str)

Use these methods to create a PrivateKey instance.
All take single string argument with private key data.
Returns class instance.

=head2 fromWif($str, $network = undef)

Takes an additional optional argument, which is network name. It may
be useful if you use many networks and some have the same WIF byte.
This method will change compression and network states of the created private key,
as this data is included in WIF format.
Will fail with 0 / undef if passed WIF string is invalid.
Will croak if it encounters a problem with network configuration.
Returns class instance.

=head2 new($instance)

Takes a single argument which must be instance of L<Crypt::PK::ECC>.
This allows you to use raw Crypt::PK::ECC methods to create key on your own.

=head2 setCompressed($val)

Change key's compression state to $val (1/0). This will change the WIF generated by
toWif() method and also enable creation of uncompressed public keys.
If $val is omitted it is set to 1.
Returns current key instance.

=head2 setNetwork($val)

Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. This will change the
WIF generated by toWif() method and also enable creation of public keys
generating this network's addresses.
Returns current key instance.

=head2 getPublicKey()

Returns instance of Bitcoin::Crypto::PublicKey generated from the private key.

=head2 signMessage($message, $algo = "sha256")

Signs a digest of $message (usinig $algo digest algorithm) with a private key.
$algo must be available in Digest package.
Returns a byte string containing signature.

=head2 verifyMessage($message, $signature, $algo = "sha256")

Verifies $signature against digest of $message (with $algo digest algorithm)
using private key.
$algo must be available in Digest package.
Returns boolean.

=head2 toHex() / toBytes() / toWif() / toBip39Mnemonic()

Returns private key representation in specified format.

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::PublicKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut

