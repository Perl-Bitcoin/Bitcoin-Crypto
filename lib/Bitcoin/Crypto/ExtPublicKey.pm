package Bitcoin::Crypto::ExtPublicKey;

use Modern::Perl "2010";
use Moo;
use Digest::SHA qw(hmac_sha512);
use Carp qw(croak);
use Math::BigInt 1.999816 try => 'GMP';
use Math::EllipticCurve::Prime;
use Math::EllipticCurve::Prime::Point;

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(ensure_length);

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
    $hmac_data .= ensure_length pack("N", $child_num), 4;

    my $data = hmac_sha512($hmac_data, $self->chainCode);
    my $chain_code = substr $data, 32, 32;

    my $el_curve = Math::EllipticCurve::Prime->from_name($config{curve_name});
    my $number = Math::BigInt->from_bytes(substr $data, 0, 32);
    my $key = $self->_createKey(substr $data, 0, 32);
    my $point = Math::EllipticCurve::Prime::Point->from_bytes($key->export_key_raw("public"));
    $point->curve($el_curve);
    my $point_cpy = $point->copy();
    my $parent_point = Math::EllipticCurve::Prime::Point->from_bytes($self->rawKey("public"));
    $parent_point->curve($el_curve);
    my $n_order = $el_curve->n;

    $point->badd($parent_point);

    croak "Key $child_num in sequence was found invalid"
        if $number->bge($n_order);

    return __PACKAGE__->new(
        $point->to_bytes,
        $chain_code,
        $child_num,
        $self->getFingerprint,
        $self->depth + 1
    );
}

1;
