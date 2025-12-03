package Bitcoin::Crypto::Helpers;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Carp qw(carp);
use MIME::Base64;
use Bitcoin::Secp256k1;

use Bitcoin::Crypto::Constants qw(USE_BIGINTS);
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
	encode_64bit
	decode_64bit
	carp_once
	parse_formatdesc
	ecc
	standard_push
	check_strict_public_key
	check_strict_der_signature
	make_strict_der_signature
	die_no_trace
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

sub encode_64bit
{
	my ($value) = @_;

	if (USE_BIGINTS) {
		return scalar reverse ensure_length $value->as_bytes, 8;
	}
	else {
		my $lower = $value & 0xffffffff;
		my $upper = $value >> 32;
		return pack 'VV', $lower, $upper;
	}
}

sub decode_64bit
{
	my ($bytes) = @_;

	if (USE_BIGINTS) {
		return Math::BigInt->from_bytes(scalar reverse $bytes);
	}
	else {
		my ($lower, $upper) = unpack 'VV', $bytes;
		return ($upper << 32) + $lower;
	}
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

sub ecc
{
	state $secp;
	state $used_times = 0;

	# define an arbitrary number of times a single secp256k1 context can be
	# used. Create a new context after that. This gives an increased security
	# according to libsecp256k1 documentation.
	if ($used_times++ > 100) {
		$secp = undef;
		$used_times = 0;
	}

	return $secp //= Bitcoin::Secp256k1->new;
}

sub standard_push
{
	my ($opcode_name, $bytes) = @_;

	# standard push is not checked for opcodes that push constant data
	return !!1 if !$opcode_name || $opcode_name =~ /OP_\d/;

	my $bytelen = length $bytes;
	if ($bytelen == 0) {

		# empty vectors are only pushed by OP_0
		return !!0;
	}
	elsif ($bytelen == 1) {
		my $ord = ord $bytes;

		# anything up to 0x10 (excluding 0x00) and 0x81 has a special push
		# opcode
		return ($ord == 0x00 || $ord > 0x10)
			&& $ord != 0x81;
	}
	elsif ($bytelen <= 75) {

		# byte lengths from 1 to 75 use OP_PUSH
		return $opcode_name eq 'OP_PUSH';
	}
	elsif ($bytelen < (1 << 8)) {

		# byte lengths fitting on 1 byte use OP_PUSHDATA1
		return $opcode_name eq 'OP_PUSHDATA1';
	}
	elsif ($bytelen < (1 << 16)) {

		# byte lengths fitting on 2 bytes use OP_PUSHDATA2
		return $opcode_name eq 'OP_PUSHDATA2';
	}
	else {

		# any other push uses OP_PUSHDATA4
		return $opcode_name eq 'OP_PUSHDATA4';
	}
}

sub check_strict_public_key
{
	my ($pubkey) = @_;

	my $len = length($pubkey);
	my $byte = substr($pubkey, 0, 1);

	return !!1 if $len == 65 && $byte eq "\x04";
	return !!1 if $len == 33 && ($byte eq "\x03" || $byte eq "\x02");

	return !!0;
}

# translated to Perl from:
# https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki#der-encoding-reference
sub check_strict_der_signature
{
	my ($signature) = @_;

	# NOTE: increment by 1 to take (stripped earlier) sighash into account
	# without changing the algorithm
	my $len = length($signature) + 1;

	return !!0
		if $len < 9 || $len > 73;

	return !!0
		if substr($signature, 0, 1) ne "\x30";

	return !!0
		if unpack('C', substr $signature, 1, 1) != $len - 3;

	my $r_len = unpack 'C', substr $signature, 3, 1;

	return !!0
		if $r_len + 5 >= $len;

	my $s_len = unpack 'C', substr $signature, 5 + $r_len, 1;

	return !!0
		if $r_len + $s_len + 7 != $len;

	for my $item ([$r_len, 2], [$s_len, $r_len + 4]) {
		return !!0
			if substr($signature, $item->[1], 1) ne "\x02";

		return !!0
			if $item->[0] == 0;

		return !!0
			if unpack('C', substr $signature, $item->[1] + 2, 1) & 0x80;

		return !!0
			if $item->[0] > 1 && substr($signature, $item->[1] + 2, 1) eq "\x00"
			&& !(unpack('C', substr $signature, $item->[1] + 3, 1) & 0x80);
	}

	return !!1;
}

# this does not fix low s, just strict encoding
sub make_strict_der_signature
{
	my ($signature) = @_;
	return '' unless length $signature;

	# https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format
	# also:
	# - ignore any trailing data
	# - fix negative r and s

	my $pos = 0;
	my $compound = substr $signature, $pos++, 1;
	my $total_len = unpack 'C', substr $signature, $pos++, 1;
	my $int1 = substr $signature, $pos++, 1;
	my $r_len = unpack 'C', substr $signature, $pos++, 1;
	my $r = substr $signature, $pos, $r_len;
	$pos += $r_len;
	my $int2 = substr $signature, $pos++, 1;
	my $s_len = unpack 'C', substr $signature, $pos++, 1;
	my $s = substr $signature, $pos, $s_len;
	$pos += $s_len;

	# remove padding
	$r = substr($r, 1)
		while unpack('C', $r) == 0;
	$s = substr($s, 1)
		while unpack('C', $s) == 0;

	# top bit may be 1, so prepend with zero to avoid being interpreted as
	# negative
	$r = "\x00$r"
		if unpack('C', $r) & 0x80;
	$s = "\x00$s"
		if unpack('C', $s) & 0x80;

	# adjust lengths
	$total_len -= $r_len + $s_len;
	$r_len = length $r;
	$s_len = length $s;
	$total_len += $r_len + $s_len;

	# return extracted strict signature
	return join '',
		$compound,
		pack('C', $total_len),
		$int1,
		pack('C', $r_len),
		$r,
		$int2,
		pack('C', $s_len),
		$s,
		;
}

sub die_no_trace
{
	die $_[0] . "\n";
}

1;

# Internal use only

