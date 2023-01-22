package Bitcoin::Crypto::Helpers;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use List::Util qw(max);
use Crypt::PK::ECC;

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;

BEGIN {
	require Math::BigInt;

	# Version 1.6003 of optional GMP is required for the from_bytes / to_bytes implementations
	if (eval { require Math::BigInt::GMP; Math::BigInt::GMP->VERSION('1.6003'); 1 }) {
		Math::BigInt->import(try => 'GMP,LTM');
	}
	else {
		Math::BigInt->import(try => 'LTM');
	}
}

our @EXPORT_OK = qw(
	new_bigint
	pad_hex
	ensure_length
	verify_bytestring
	hash160
	hash256
	add_ec_points
);

sub new_bigint
{
	my ($bytes) = @_;
	return Math::BigInt->from_hex(unpack 'H*', $bytes);
}

sub pad_hex
{
	my ($hex) = @_;
	$hex =~ s/\A0x//;
	return '0' x (length($hex) % 2) . $hex;
}

sub ensure_length
{
	my ($packed, $bytelen) = @_;
	my $missing = $bytelen - length $packed;

	Bitcoin::Crypto::Exception->raise(
		"packed string exceeds maximum number of bytes allowed ($bytelen)"
	) if $missing < 0;

	return pack("x$missing") . $packed;
}

sub verify_bytestring
{
	my ($string) = @_;

	Bitcoin::Crypto::Exception->raise(
		'invalid input value, expected string'
	) if !defined $string || ref $string;

	my @characters = split //, $string;

	Bitcoin::Crypto::Exception->raise(
		'string contains characters with numeric values over 255 and cannot be used as a byte string'
	) if (grep { ord($_) > 255 } @characters) > 0;
}

sub hash160
{
	my ($data) = @_;

	return ripemd160(sha256($data));
}

sub hash256
{
	my ($data) = @_;

	return sha256(sha256($data));
}

# Self-contained implementation on elliptic curve points addition.
# This is only a partial implementation, but should be good enough for key
# derivation needs. Code borrowed from the archived Math::EllipticCurve::Prime
# module. Returns undef for infinity points, expects to get a valid uncompressed
# point data on input
sub add_ec_points
{
	my ($point1, $point2) = @_;

	my $curve_size = Bitcoin::Crypto::Constants::key_max_length;
	my $curve_data = Crypt::PK::ECC->new->generate_key(Bitcoin::Crypto::Constants::curve_name)->curve2hash;
	my $p = new_bigint(pack 'H*', $curve_data->{prime});
	my $a = new_bigint(pack 'H*', $curve_data->{A});

	my $add_points = sub {
		my ($x1, $x2, $y1, $lambda) = @_;

		my $x = $lambda->copy->bmodpow(2, $p);
		$x->bsub($x1);
		$x->bsub($x2);
		$x->bmod($p);

		my $y = $x1->copy->bsub($x);
		$y->bmul($lambda);
		$y->bsub($y1);
		$y->bmod($p);

		return {x => $x, y => $y};
	};

	my $double = sub {
		my ($x, $y) = @_;
		my $lambda = $x->copy->bmodpow(2, $p);
		$lambda->bmul(3);
		$lambda->badd($a);
		my $bottom = $y->copy->bmul(2)->bmodinv($p);
		$lambda->bmul($bottom)->bmod($p);

		return $add_points->($x, $x, $y, $lambda);
	};

	my $format = "(a$curve_size)*";
	my ($px1, $py1) = map { new_bigint($_) } unpack $format, substr $point1, 1;
	my ($px2, $py2) = map { new_bigint($_) } unpack $format, substr $point2, 1;

	my $ret = sub {
		if ($px1->bcmp($px2)) {
			my $lambda = $py2->copy->bsub($py1);
			my $bottom = $px2->copy->bsub($px1)->bmodinv($p);
			$lambda->bmul($bottom)->bmod($p);

			return $add_points->($px1, $px2, $py1, $lambda);
		}
		elsif ($py1->is_zero || $py2->is_zero || $py1->bcmp($py2)) {
			return undef;
		}
		else {
			return $double->($px1, $py1);
		}
		}
		->();

	my $exp_x = $ret->{x}->to_bytes;
	my $exp_y = $ret->{y}->to_bytes;

	return defined $ret
		? "\x04" .
		ensure_length($exp_x, $curve_size) .
		ensure_length($exp_y, $curve_size)
		: undef;
}

1;

# Internal use only

