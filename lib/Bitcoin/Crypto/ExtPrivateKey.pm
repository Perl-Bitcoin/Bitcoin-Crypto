package Bitcoin::Crypto::ExtPrivateKey;

use Modern::Perl "2010";
use Moo;
use Digest::SHA qw(hmac_sha512);
use Math::BigInt 1.999816 try => 'GMP';
use Math::EllipticCurve::Prime;
use Carp qw(croak);

use Bitcoin::Crypto::ExtPublicKey;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(ensure_length);

with "Bitcoin::Crypto::Roles::ExtendedKey";


sub _isPrivate { 1 }

sub toBip39Mnemonic
{
    my ($self) = @_;
    my ($entropy) = $self->rawKey;
    return entropy_to_bip39_mnemonic(entropy => $entropy);
}

sub fromBip39Mnemonic
{
    my ($class, $mnemonic, $password) = @_;
    $password = "mnemonic" . ($password // "");
    my $bytes = bip39_mnemonic_to_entropy(mnemonic => $mnemonic);
    for (1 .. 2048) {
        $bytes = hmac_sha512($bytes, $password);
    }
    my $key = substr $bytes, 0, 32;
    my $cc = substr $bytes, 32, 32;
    return $class->new($key, $cc);
}

sub fromSeed
{
    my ($class, $seed) = @_;
    my $bytes = hmac_sha512($seed, "Bitcoin seed");
    my $key = substr $bytes, 0, 32;
    my $cc = substr $bytes, 32, 32;

    return $class->new($key, $cc);
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
