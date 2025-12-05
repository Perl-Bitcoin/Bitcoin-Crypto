package Bitcoin::Crypto::Helpers;

use v5.14;
use warnings;
use Exporter qw(import);
use Carp qw(croak carp);
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
	my $value = shift;

	if (USE_BIGINTS) {
		return scalar reverse ensure_length $value->as_bytes, 8;
	}
	else {
		return pack 'VV', $value & 0xffffffff, $value >> 32;
	}
}

sub decode_64bit
{
	my $bytes = shift;

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
	elsif ($type ne 'bytes') {
		croak "bad format type: $type";
	}

	return $data;
}

# define an arbitrary number of times a single secp256k1 context can be
# used. Create a new context after that. This gives an increased security
# according to libsecp256k1 documentation.
use constant ECC_MAX_USES => 100;

sub ecc
{
	state $secp;
	state $used_times = ECC_MAX_USES;

	if (++$used_times > ECC_MAX_USES) {
		$secp = Bitcoin::Secp256k1->new;
		$used_times = 0;
	}

	return $secp;
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

	if ($bytelen == 1) {
		my $ord = ord $bytes;

		# anything up to 0x10 (excluding 0x00) and 0x81 has a special push
		# opcode
		return !!0
			unless ($ord == 0x00 || $ord > 0x10)
			&& $ord != 0x81;
	}

	if ($bytelen <= 75) {

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
	my $byte = unpack('C', $pubkey);

	return !!1 if $len == 65 && $byte == 0x04;
	return !!1 if $len == 33 && ($byte == 0x03 || $byte == 0x02);

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

	my ($t1, $t2, $t3, $r_len, $s_len);
	($t1, $t2, $r_len) = unpack 'CC @3C', $signature;

	# check start and r length
	return !!0
		if $t1 != 0x30
		|| $t2 != $len - 3
		|| $r_len + 5 >= $len;

	$s_len = unpack '@' . (5 + $r_len) . 'C', $signature;

	# check s length
	return !!0
		if $r_len + $s_len + 7 != $len;

	for my $item ([$r_len, 2], [$s_len, $r_len + 4]) {
		($t1, $t2, $t3) = unpack '@0C @2C @3C', substr $signature, $item->[1];

		# check parts of r or s
		return !!0
			if $t1 != 0x02
			|| $item->[0] == 0
			|| $t2 & 0x80
			|| ($item->[0] > 1 && $t2 == 0 && !($t3 & 0x80));
	}

	return !!1;
}

# this does not fix low s, just strict encoding
sub make_strict_der_signature
{
	my ($signature) = @_;
	return $signature unless length $signature >= 8;

	# https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format
	# also:
	# - ignore any trailing data
	# - fix negative r and s

	my ($compound, $total_len, $int1, $r_len) = unpack 'aCaC', $signature;
	my $r = substr $signature, 4, $r_len;

	$signature = substr $signature, 4 + $r_len;
	my ($int2, $s_len) = unpack 'aC', $signature;
	my $s = substr $signature, 2, $s_len;

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
	$r_len = length $r;
	$s_len = length $s;
	$total_len = 4 + $r_len + $s_len;

	# return extracted strict signature
	return pack "aCaCa*aCa*", $compound, $total_len, $int1, $r_len, $r, $int2, $s_len, $s;
}

sub die_no_trace
{
	die $_[0] . "\n";
}

1;

# Internal use only

