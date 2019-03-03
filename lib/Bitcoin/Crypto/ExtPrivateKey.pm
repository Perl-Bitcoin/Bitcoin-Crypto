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
