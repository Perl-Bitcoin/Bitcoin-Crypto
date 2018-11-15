package Bitcoin::Crypto::Roles::Key;

use Modern::Perl "2010";
use Moo::Role;
use MooX::Types::MooseLike::Base qw(:all);
use Digest::SHA qw(sha256);
use Crypt::PK::ECC;

use Bitcoin::Crypto::Util qw(pack_hex);
use Bitcoin::Crypto::Network qw(get_default_network get_network validate_network);
use Bitcoin::Crypto::Config;

has "keyInstance" => (
    is => "ro",
    isa => InstanceOf["Crypt::PK::ECC"]
);

has "network" => (
    is => "rw",
    isa => HashRef,
    default => sub {
        return get_default_network();
    },
    writer => "_setNetwork"
);

has "compressed" => (
    is => "rw",
    isa => Bool,
    default => $config{compress_public_point},
    writer => "setCompressed"
);

sub verifyMessage
{
    my ($self, $message, $signature, $algorithm) = @_;
    $algorithm //= "sha256";
    return $self->keyInstance->verify_message($signature, $message, $algorithm);
}

sub fromHex
{
    my ($class, $val) = @_;
    return $class->fromBytes(pack_hex($val));
}

sub toHex
{
    my ($self) = @_;
    return unpack "H*", $self->toBytes();
}

sub toBytes
{
    my ($self) = @_;
    return $self->rawKey;
}

sub setNetwork
{
    my ($self, $network) = @_;
    if (ref $network eq "HASH") {
        validate_network($network);
    } else {
        $network = get_network($network);
    }
    $self->_setNetwork($network);
}

1;
