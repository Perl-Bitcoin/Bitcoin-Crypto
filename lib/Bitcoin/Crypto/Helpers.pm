package Bitcoin::Crypto::Helpers;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);
use Carp qw(carp);
use MIME::Base64;
use Bitcoin::Secp256k1;

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
	ecc
	standard_push
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
	if ($used_times++ > 20) {
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

1;

# Internal use only

