package Bitcoin::Crypto::ExtPrivateKey;

use Modern::Perl "2010";
use Moo;
use Digest::SHA qw(sha512);
use Digest::HMAC qw(hmac);

use Bitcoin::Crypto::ExtPublicKey;
use Bitcoin::Crypto::Config;

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

1;
