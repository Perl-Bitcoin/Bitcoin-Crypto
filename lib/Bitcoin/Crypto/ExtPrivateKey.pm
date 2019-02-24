package Bitcoin::Crypto::ExtPrivateKey;

use Modern::Perl "2010";
use Moo;
use Digest::SHA qw(sha512);
use Digest::HMAC qw(hmac);
use Math::BigInt 1.999816 try => 'GMP';
use Math::EllipticCurve::Prime;

use Bitcoin::Crypto::ExtPublicKey;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(ensure_length);

with "Bitcoin::Crypto::Roles::ExtendedKey";


sub _isPrivate { 1 }

sub toBip39Mnemonic
{
    my ($self) = @_;
    my ($entropy) = $self->toBytes();
    return entropy_to_bip39_mnemonic(entropy => $entropy);
}

sub fromBip39Mnemonic
{
    my ($class, $mnemonic, $password) = @_;
    $password = "mnemonic" . ($password // "");
    my $bytes = bip39_mnemonic_to_entropy(mnemonic => $mnemonic);
    for (1 .. 2048) {
        $bytes = hmac($bytes, $password, \&sha512);
    }
    my $key = substr $bytes, 0, 32;
    my $cc = substr $bytes, 32, 32;
    return $class->fromBytes($key, $cc);
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
    $hmac_data .= ensure_length pack("C", $child_num), 4;

    my $data = hmac($hmac_data, $self->chainCode, \&sha512);
    my $chain_code = substr $data, 32, 32;

    my $number = Math::BigInt->from_bytes(substr $data, 0, 32);
    my $num_cpy = $number->copy();
    my $key_num = Math::BigInt->from_bytes($self->rawKey);
    my $n_order = Math::EllipticCurve::Prime->from_name($config{curve_name})->n;

    $number->add($key_num);
    $number->bmod($n_order);

    croak "Key $child_num in sequence was found invalid";
        if $num_cpy->bge($n_order) || $number->beq(0);

    return __PACKAGE__->new(
        $number->as_bytes,
        $chain_code,
        $child_num,
        $self->getFingerprint,
        $self->depth + 1
    );
}

1;
