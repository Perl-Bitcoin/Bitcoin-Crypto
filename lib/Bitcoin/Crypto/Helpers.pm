package Bitcoin::Crypto::Helpers;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use List::Util qw(max);
use Crypt::PK::ECC;
use Carp qw(carp);

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
	pack_varint
	unpack_varint
	carp_once
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

sub pack_varint
{
	my ($value) = @_;

	Bitcoin::Crypto::Exception->raise(
		"VarInt must be positive or zero"
	) if $value < 0;

	if ($value <= 0xfc) {
		return pack 'C', $value;
	}
	elsif ($value <= 0xffff) {
		return "\xfd" . pack 'v', $value;
	}
	elsif ($value <= 0xffffffff) {
		return "\xfe" . pack 'V', $value;
	}
	else {
		# 32 bit archs should not reach this
		return "\xff" . (pack 'V', $value & 0xffffffff) . (pack 'V', $value >> 32);
	}
}

sub unpack_varint
{
	my ($stream) = @_;

	my $value = ord substr $stream, 0, 1, '';
	my $length = 1;

	if ($value == 0xfd) {
		Bitcoin::Crypto::Exception->raise(
			"cannot unpack VarInt: not enough data in stream"
		) if length $stream < 2;

		$value = unpack 'v', substr $stream, 0, 2;
		$length += 2;
	}
	elsif ($value == 0xfe) {
		Bitcoin::Crypto::Exception->raise(
			"cannot unpack VarInt: not enough data in stream"
		) if length $stream < 4;

		$value = unpack 'V', substr $stream, 0, 4;
		$length += 4;
	}
	elsif ($value == 0xff) {
		Bitcoin::Crypto::Exception->raise(
			"cannot unpack VarInt: no 64 bit support"
		) if !Bitcoin::Crypto::Constants::is_64bit;

		Bitcoin::Crypto::Exception->raise(
			"cannot unpack VarInt: not enough data in stream"
		) if length $stream < 8;

		my $lower = unpack 'V', substr $stream, 0, 4;
		my $higher = unpack 'V', substr $stream, 4, 4;
		$value = ($higher << 32) + $lower;
		$length += 8;
	}

	return ($length, $value);
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

# not exported - used exclusively by the internal FormatDesc type

sub parse_formatdesc
{
	my ($type, $data) = @{$_[0]};

	if ($type eq 'hex') {
		$data = pack 'H*', pad_hex $data;
	}
	elsif ($type eq 'base58') {
		require Bitcoin::Crypto::Base58;
		$data = Bitcoin::Crypto::Base58::decode_base58check($data);
	}

	return $data;
}

1;

# Internal use only

