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
	state $used_times = 'inf';

	# define an arbitrary number of times a single secp256k1 context can be
	# used. Create a new context after that. This gives an increased security
	# according to libsecp256k1 documentation.
	if ($used_times++ > 20) {
		$secp = Bitcoin::Secp256k1->new;
		$used_times = 0;
	}

	return $secp;
}

1;

# Internal use only

