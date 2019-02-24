package Bitcoin::Crypto::ExtPublicKey;

use Modern::Perl "2010";
use Moo;
use Digest::SHA qw(sha512);
use Digest::HMAC qw(hmac);
use Math::BigInt 1.999816 try => 'GMP';
use Math::EllipticCurve::Prime;
use Math::EllipticCurve::Prime::Point;

with "Bitcoin::Crypto::Roles::ExtendedKey";

sub _isPrivate { 0 }

sub _deriveKeyPartial
{
    my ($self, $child_num, $hardened) = @_;

    croak "Cannot derive hardened key from public key"
        if $hardened;

    # public key data - SEC compressed form
    my $hmac_data = $self->rawKey("public_compressed");
    # child number - 4 bytes
    $hmac_data .= ensure_length pack("C", $child_num), 4;

    my $data = hmac($hmac_data, $self->chainCode, \&sha512);
    my $chain_code = substr $data, 32, 32;

    my $number = Math::BigInt->from_bytes(substr $data, 0, 32);
    my $key = $self->_createKey(substr $data, 0, 32);
    my $point = Math::EllipticCurve::Prime::Point->from_hex($key->export_key_raw("public"));
    $point->curve($config{curve_name});
    my $point_cpy = $point->copy();
    my $parent_point = Math::EllipticCurve::Prime::Point->from_hex($self->rawKey("public"));
    $parent_point->curve($config{curve_name});
    my $n_order = Math::EllipticCurve::Prime->from_name($config{curve_name})->n;

    $point->badd($parent_point);

    croak "Key $child_num in sequence was found invalid";
        if $number->bge($n_order) || $point->infinity;

    return __PACKAGE__->new(
        $point->to_bytes,
        $chain_code,
        $child_num,
        $self->getFingerprint,
        $self->depth + 1
    );
}

1;
