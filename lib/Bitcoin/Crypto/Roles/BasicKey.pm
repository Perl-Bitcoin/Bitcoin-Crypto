package Bitcoin::Crypto::Roles::BasicKey;

use Modern::Perl "2010";
use Moo::Role;
use MooX::Types::MooseLike::Base qw(InstanceOf);
use Digest::SHA qw(sha256);
use Crypt::PK::ECC;
use Carp qw(croak);
use Try::Tiny;

use Bitcoin::Crypto::Helpers qw(pad_hex);
use Bitcoin::Crypto::Config;

has "keyInstance" => (
    is => "ro",
    isa => InstanceOf["Crypt::PK::ECC"]
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
    return $class->fromBytes(pack "H*", pad_hex($val));
}

sub toHex
{
    my ($self) = @_;
    return unpack "H*", $self->toBytes();
}

sub fromBytes
{
    my ($class, $bytes) = @_;

    my $key = Crypt::PK::ECC->new();
    my $missing = $config{key_max_length} - length $bytes;
    $bytes = pack("x$missing") . $bytes if $missing > 0;
    try {
        $key->import_key_raw($bytes, $config{curve_name});
    } catch {
        croak "Error creating key - check input data";
    };

    return $class->new($key);
}

sub toBytes
{
    my ($self) = @_;
    return $self->rawKey;
}

1;
