package Bitcoin::Crypto::Roles::ExtendedKey;

use Modern::Perl "2010";
use Moo::Role;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Digest::SHA qw(sha256);
use Carp qw(croak);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Types qw(IntMaxBits StrExactLength);
use Bitcoin::Crypto::PrivateKey;
use Bitcoin::Crypto::PublicKey;
use Bitcoin::Crypto::Helpers qw(pad_hex ensure_length);

with "Bitcoin::Crypto::Roles::Key";

has "depth" => (
    is => "ro",
    isa => IntMaxBits[4],
    default => 0
);

has "parentFingerprint" => (
    is => "ro",
    isa => StrExactLength[4],
    default => sub { pack "x4" }
);

has "childNumber" => (
    is => "ro",
    isa => IntMaxBits[4],
    default => 0
);

has "chainCode" => (
    is => "ro",
    isa => StrExactLength[32]
);

sub _buildArgs
{
    my ($class, @params) = @_;

    croak "Invalid arguments passed to key constructor"
        if @params < 2 || @params > 5;

    return
        keyInstance => $class->_createKey($params[0]),
        chainCode => $params[1],
        childNumber => $params[2],
        parentFingerprint => $params[3],
        depth => $params[4];
}

sub toSerialized
{
    my ($self) = @_;

    my $network_key = "ext" . ($self->_isPrivate ? "prv" : "pub") . "_version";
    my $version = $self->network->{$network_key};
    # network field is not required, lazy check for completeness
    croak "Incomplete network configuration: No $network_key found"
        unless defined $version;

    # version number (4B)
    my $serialized = ensure_length pack("C", $version), 4;
    # depth (1B)
    $serialized .= ensure_length pack("C", $self->depth), 1;
    # parent's fingerprint (4B) - ensured
    $serialized .= $self->parentFingerprint;
    # child number (4B)
    $serialized .= ensure_length pack("C", $self->childNumber), 4;
    # chain code (32B) - ensured
    $serialized .= $self->chainCode;
    # additional 1B for private keys
    $serialized .= pack "x" if $self->_isPrivate;
    # key entropy (32B)
    $serialized .= ensure_length $self->rawKey, $config{key_max_length};

    return $serialized;
}

sub fromSerialized
{
    my ($class, $serialized) = @_;

    return $class->new();
}

sub toSerializedBase58
{
    my ($self) = @_;
    my $serialized = $self->toSerialized();
    return encode_base58check $serialized;
}

sub fromSerializedBase58
{
    my ($class, $base58) = @_;
    return $class->fromSerialized(decode_base58check $base58);
}

sub getBasicKey
{
    my ($self) = @_;
    my $entropy = $self->rawKey;
    my $base_class = "Bitcoin::Crypto::" . ($self->_isPrivate ? "PrivateKey" : "PublicKey");
    my $basic_key =  $base_class->fromBytes($entropy);
    $basic_key->setNetwork($self->network);

    return $basic_key;
}

sub getFingerprint
{
    my ($self) = @_;
    my $pubkey = $this-rawKey("public_compressed");

    my $identifier = ripemd160(sha256($pubkey));
    return substr $identifier, 0, 4;
}

1;
