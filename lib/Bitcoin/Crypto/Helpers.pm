package Bitcoin::Crypto::Helpers;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Crypt::PK::ECC;
use Carp qw(carp);
use MIME::Base64;

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
	pad_hex
	ensure_length
	add_ec_points
	carp_once
	parse_formatdesc
);

our @CARP_NOT;
my %warned;

sub carp_once
{
	my ($msg) = @_;

	return if $warned{$msg};
	$warned{$msg} = 1;
	local @CARP_NOT = ((caller)[0]);
	carp($msg);
}

sub pad_hex
{
	my ($hex) = @_;
	$hex =~ s/\A0x//;
	$hex =~ tr/0-9a-fA-F//cd;
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
	my $p = Math::BigInt->from_hex($curve_data->{prime});
	my $a = Math::BigInt->from_hex($curve_data->{A});

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
	my ($px1, $py1) = map { Math::BigInt->from_bytes($_) } unpack $format, substr $point1, 1;
	my ($px2, $py2) = map { Math::BigInt->from_bytes($_) } unpack $format, substr $point2, 1;

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

# default operation is to decode based on formatdesc
# passing $reverse makes it encode instead
sub parse_formatdesc
{
	my ($type, $data, $reverse) = @_;

	if ($type eq 'hex') {
		$data = $reverse
			? unpack 'H*', $data
			: pack 'H*', pad_hex $data
			;
	}
	elsif ($type eq 'base58') {
		require Bitcoin::Crypto::Base58;
		$data = $reverse
			? Bitcoin::Crypto::Base58::encode_base58check($data)
			: Bitcoin::Crypto::Base58::decode_base58check($data)
			;
	}
	elsif ($type eq 'base64') {
		$data = $reverse
			? encode_base64($data, '')
			: decode_base64($data)
			;
	}

	return $data;
}

1;

# Internal use only

