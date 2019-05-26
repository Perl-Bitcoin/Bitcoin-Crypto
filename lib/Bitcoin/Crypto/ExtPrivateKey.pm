package Bitcoin::Crypto::ExtPrivateKey;

use Modern::Perl "2010";
use Moo;
use Digest::SHA qw(hmac_sha512);
use Math::BigInt 1.999816 try => 'GMP';
use Math::EllipticCurve::Prime;
use Carp qw(croak);
use Encode qw(encode decode);
use Unicode::Normalize;
use Bitcoin::BIP39 qw(gen_bip39_mnemonic bip39_mnemonic_to_entropy);
use PBKDF2::Tiny qw(derive);

use Bitcoin::Crypto::ExtPublicKey;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(pad_hex ensure_length);

with "Bitcoin::Crypto::Roles::ExtendedKey";

sub _isPrivate { 1 }

sub generateMnemonic
{
    my ($class, $len, $lang) = @_;
    my ($min_len, $len_div, $max_len) = (128, 32, 256);
    $len //= $min_len;
    $lang //= "en";
    # bip39 specification values
    croak "Required entropy of between $min_len and $max_len bits, divisible by $len_div"
        if $len < $min_len || $len > $max_len || $len % $len_div != 0;

    my $ret = gen_bip39_mnemonic(bits => $len, language => $lang);
    return $ret->{mnemonic};
}

sub fromMnemonic
{
    my ($class, $mnemonic, $password, $lang) = @_;
    $mnemonic = encode("UTF-8", NFKD(decode("UTF-8", $mnemonic)));
    $password = encode("UTF-8", NFKD(decode("UTF-8", "mnemonic" . ($password // ""))));

    if (defined $lang) {
        # checks validity of seed in given language
        # requires Wordlist::LANG::BIP39 module for given LANG
        bip39_mnemonic_to_entropy(mnemonic => $mnemonic, language => $lang);
    }
    my $bytes = derive("SHA-512", $mnemonic, $password, 2048);

    return $class->fromSeed($bytes);
}

sub fromSeed
{
    my ($class, $seed) = @_;
    my $bytes = hmac_sha512($seed, "Bitcoin seed");
    my $key = substr $bytes, 0, 32;
    my $cc = substr $bytes, 32, 32;

    return $class->new($key, $cc);
}

sub fromHexSeed
{
    my ($class, $seed) = @_;

    return $class->fromSeed(pack "H*", pad_hex $seed);
}

sub getPublicKey
{
    my ($self) = @_;

    my $public = Bitcoin::Crypto::ExtPublicKey->new(
        $self->rawKey("public"),
        $self->chainCode,
        $self->childNumber,
        $self->parentFingerprint,
        $self->depth
    );
    $public->setNetwork($self->network);

    return $public;
}

sub _deriveKeyPartial
{
    my ($self, $child_num, $hardened) = @_;

    my $hmac_data;
    if ($hardened) {
        # zero byte
        $hmac_data .= pack("x");
        # key data - 32 bytes
        $hmac_data .= ensure_length $self->rawKey, $config{key_max_length};
    } else {
        # public key data - SEC compressed form
        $hmac_data .= $self->rawKey("public_compressed");
    }
    # child number - 4 bytes
    $hmac_data .= ensure_length pack("N", $child_num), 4;

    my $data = hmac_sha512($hmac_data, $self->chainCode);
    my $chain_code = substr $data, 32, 32;

    my $number = Math::BigInt->from_bytes(substr $data, 0, 32);
    my $key_num = Math::BigInt->from_bytes($self->rawKey);
    my $n_order = Math::EllipticCurve::Prime->from_name($config{curve_name})->n;
    croak "Key $child_num in sequence was found invalid"
        if $number->bge($n_order);

    $number->badd($key_num);
    $number->bmod($n_order);

    return __PACKAGE__->new(
        $number->as_bytes,
        $chain_code,
        $child_num,
        $self->getFingerprint,
        $self->depth + 1
    );
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::ExtPrivateKey - class for Bitcoin extended private keys

=head1 SYNOPSIS

  use Bitcoin::Crypto::ExtPrivateKey;

  # generate mnemonic words first
  my $mnemonic = Bitcoin::Crypto::ExtPrivateKey->generateMnemonic;
  print "Your mnemonic is: $mnemonic";

  # create ExtPrivateKey from mnemonic (without password)
  my $key = Bitcoin::Crypto::ExtPrivateKey->fromMnemonic($mnemonic);
  my $ser_key = $key->toSerializedBase58;
  print "Your exported master key is: $ser_key";

  # derive child private key
  my $path = "m/0'";
  my $child_key = $key->deriveKey($path);
  my $ser_child_key = $child_key->toSerializedBase58;
  print "Your exported $path child key is: $ser_child_key";

  # create basic keypair
  my $basic_private = $child_key->getBasicKey;
  my $basic_public = $child_key->getPublicKey->getBasicKey;

=head1 DESCRIPTION

This class allows you to create an extended private key instance.

You can use an extended private key to:

=over 2

=item * generate extended public keys

=item * derive extended keys using a path

=item * restore keys from mnemonic codes, seeds and base58 format

=back

see L<Bitcoin::Crypto::Network> if you want to work with other networks than Bitcoin Mainnet.

=head1 METHODS

=head2 generateMnemonic

  sig: generateMnemonic($class, $len = 128, $lang = "en")
Generates a new valid mnemonic code. Default entropy is 128 bits.
With $len this can be changed to up to 256 bits with 32 bit step.
Other languages than english require additional modules for L<Bitcoin::BIP39>.
Croaks when $len is invalid (under 128, above 256 or not divisible by 32).
Returns newly generated BIP39 mnemonic string.

=head2 fromMnemonic

  sig: fromMnemonic($class, $mnemonic, $password = "", $lang = undef)
Creates a new key from given mnemonic and password.
Note that technically any password is correct and there's no way to tell if it was mistaken.
If you need to validate if $mnemonic is a valid mnemonic you should specify $lang, e.g. "en".
If no $lang is given then any string passed as $mnemonic will produce a valid key.
Returns a new instance of this class.

=head2 fromSeed

  sig: fromSeed($class, $seed)
Creates and returns a new key from seed, which can be any data of any length.
$seed is expected to be a byte string.

=head2 fromHexSeed

  sig: fromHexSeed($class, $seed)
Same as fromSeed, but $seed is treated as hex string.

=head2 toSerialized

  sig: toSerialized($self)
Returns the key serialized in format specified in BIP32 as byte string.

=head2 toSerializedBase58

  sig: toSerializedBase58($self)
Behaves the same as toSerialized(), but performs Base58Check encoding
on the resulting byte string.

=head2 fromSerialized

  sig: fromSerialized($class, $serialized, $network = undef)
Tries to unserialize byte string $serialized with format specified in BIP32.
Croaks on errors. If multiple networks match serialized data specify $network
manually (id of the network) to avoid exception.

=head2 fromSerializedBase58

  sig: fromSerializedBase58($class, $base58, $network)
Same as fromSerialized, but performs Base58Check decoding on $base58 argument.

=head2 setNetwork

  sig: setNetwork($self, $val)
Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. 
Returns current key instance.

=head2 getPublicKey

  sig: getPublicKey($self)
Returns instance of L<Bitcoin::Crypto::ExtPublicKey> generated from the private key.

=head2 getBasicKey

  sig: getBasicKey($self)
Returns the key in basic format: L<Bitcoin::Crypto::PrivateKey>

=head2 deriveKey

  sig: deriveKey($self, $path)
Performs extended key deriviation as specified in BIP32 on the current key
with $path. Croaks on error.
See BIP32 document for details on deriviation paths and methods.
Returns a new extended key instance - result of a deriviation.

=head2 getFingerprint

  sig: getFingerprint($self, $len = 4)
Returns a fingerprint of the extended key of $len length (byte string)

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::ExtPublicKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut

