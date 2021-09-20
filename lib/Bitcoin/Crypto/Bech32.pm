package Bitcoin::Crypto::Bech32;

our $VERSION = "1.001";

use v5.10;
use warnings;
use Exporter qw(import);
use Types::Standard qw(Str);
use Carp qw(croak);

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(verify_bytestring);
use Bitcoin::Crypto::Segwit qw(validate_program);

our @EXPORT_OK = qw(
	translate_5to8
	translate_8to5
	encode_bech32
	decode_bech32
	encode_segwit
	decode_segwit
);

use constant BECH32 => 'bech32';
use constant BECH32M => 'bech32m';

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

my $CHECKSUM_SIZE = 6;
my $BECH32M_CONSTANT = 0x2bc830a3;

my @alphabet = qw(
	q p z r y 9 x 8
	g f 2 t v d w 0
	s 3 j n 5 4 k h
	c e 6 m u a 7 l
);

my %alphabet_mapped = map { $alphabet[$_] => $_ } 0 .. $#alphabet;

sub polymod
{
	my ($values) = @_;
	my @consts = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
	my $chk = 1;
	for my $val (@$values) {
		my $b = ($chk >> 25);
		$chk = ($chk & 0x1ffffff) << 5 ^ $val;
		for (0 .. 4) {
			$chk ^= ((($b >> $_) & 1) ? $consts[$_] : 0);
		}
	}
	return $chk;
}

sub hrp_expand
{
	my @hrp = split "", shift;
	my (@part1, @part2);
	for (@hrp) {
		my $val = ord;
		push @part1, $val >> 5;
		push @part2, $val & 31;
	}
	return [@part1, 0, @part2];
}

sub to_numarr
{
	my ($string) = @_;

	return [map { $alphabet_mapped{$_} } split "", $string];
}

sub create_checksum
{
	my ($hrp, $data) = @_;
	my $polymod = polymod([@{hrp_expand $hrp}, @{to_numarr $data}, (0) x $CHECKSUM_SIZE]) ^ 1;
	my $checksum;
	for (0 .. $CHECKSUM_SIZE - 1) {
		$checksum .= $alphabet[($polymod >> 5 * (5 - $_)) & 31];
	}
	return $checksum;
}

sub create_checksum_bech32m
{
	my ($hrp, $data) = @_;
	my $polymod = polymod([@{hrp_expand $hrp}, @{to_numarr $data}, (0) x $CHECKSUM_SIZE]) ^ $BECH32M_CONSTANT;
	my $checksum;
	for (0 .. $CHECKSUM_SIZE - 1) {
		$checksum .= $alphabet[($polymod >> 5 * (5 - $_)) & 31];
	}
	return $checksum;
}

sub verify_checksum
{
	my ($hrp, $data) = @_;
	return polymod([@{hrp_expand $hrp}, @{to_numarr $data}]) == 1;
}

sub verify_checksum_bech32m
{
	my ($hrp, $data) = @_;
	return polymod([@{hrp_expand $hrp}, @{to_numarr $data}]) == $BECH32M_CONSTANT;
}

sub split_bech32
{
	my ($bech32enc) = @_;

	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"bech32 input is not a string"
	) unless Str->check($bech32enc);

	$bech32enc = lc $bech32enc
		if uc $bech32enc eq $bech32enc;

	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"bech32 string too long"
	) if length $bech32enc > 90;

	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"bech32 string contains mixed case"
	) if lc $bech32enc ne $bech32enc;

	my @parts = split "1", $bech32enc;

	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"bech32 separator character missing"
	) if @parts < 2;

	my $data = pop @parts;

	@parts = (join("1", @parts), $data);

	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"incorrect length of bech32 human readable part"
	) if length $parts[0] < 1 || length $parts[0] > 83;

	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"illegal characters in bech32 human readable part"
	) if $parts[0] !~ /^[\x21-\x7e]+$/;

	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"incorrect length of bech32 data part"
	) if length $parts[1] < 6;

	my $chars = join "", @alphabet;
	Bitcoin::Crypto::Exception::Bech32InputFormat->raise(
		"illegal characters in bech32 data part"
	) if $parts[1] !~ /^[$chars]+$/;

	return @parts;
}

# used during segwit address decoding
sub translate_5to8
{
	my ($values_ref) = @_;
	my @enc_values = @{$values_ref};

	my $bits = unpack "B*", pack "C*", @enc_values;
	$bits = join "", map { substr $_, 3 } unpack "(a8)*", $bits;

	my $length_padded = length $bits;
	my $padding = $length_padded % 8;
	$bits =~ s/0{$padding}$//;

	Bitcoin::Crypto::Exception::Bech32InputData->raise(
		"incorrect padding encoded in bech32"
	) if length($bits) % 8 != 0 || length($bits) < $length_padded - 4;

	my @data = unpack "(a8)*", $bits;
	my $result = "";
	for my $bitstr (@data) {
		$result .= pack "B8", $bitstr;
	}
	return $result;
}

# used during segwit address encoding
sub translate_8to5
{
	my ($bytes) = @_;
	verify_bytestring($bytes);

	my @data = unpack "(a5)*", unpack "B*", $bytes;
	my @result;
	for my $bitstr (@data) {
		my $pad = 5 - length $bitstr;
		my $num = unpack "C", pack "B*", "000$bitstr" . 0 x $pad;
		push @result, $num;
	}

	return \@result;
}

sub encode_base32
{
	my ($array) = @_;

	my $result = '';
	for my $num (@{$array}) {
		Bitcoin::Crypto::Exception::Bech32InputData->raise(
			"incorrect number to be encoded in bech32: must be between 0 and 31"
		) unless defined $alphabet[$num];
		$result .= $alphabet[$num];
	}

	return $result;
}

sub decode_base32
{
	my ($encoded) = @_;

	my @enc_values = map { $alphabet_mapped{$_} } split //, $encoded;

	return \@enc_values;
}

sub encode_bech32
{
	my ($hrp, $data, $type) = @_;
	$type //= BECH32;

	my $result = encode_base32($data);
	my $checksum;

	if ($type eq BECH32) {
		$checksum = create_checksum($hrp, $result);
	}
	elsif ($type eq BECH32M) {
		$checksum = create_checksum_bech32m($hrp, $result);
	}
	else {
		croak 'invalid type: neither bech32 nor bech32m';
	}

	return $hrp . 1 . $result . $checksum;
}

sub encode_segwit
{
	my ($hrp, $bytes) = @_;

	my $version = validate_program($bytes);
	return encode_bech32($hrp, [$version, @{translate_8to5(substr $bytes, 1)}], $version == 0 ? BECH32 : BECH32M);
}

sub decode_bech32
{
	my ($hrp, $data) = split_bech32 @_;

	my $type;
	$type = BECH32
		if verify_checksum($hrp, $data);
	$type = BECH32M
		if !$type && verify_checksum_bech32m($hrp, $data);

	Bitcoin::Crypto::Exception::Bech32InputChecksum->raise(
		"incorrect bech32 checksum"
	) unless $type;

	return ($hrp, decode_base32(substr $data, 0, -$CHECKSUM_SIZE), $type);
}

sub decode_segwit
{
	my ($hrp, $data, $type) = decode_bech32 @_;
	my $ver = shift @{$data};

	Bitcoin::Crypto::Exception::Bech32InputChecksum->raise(
		"wrong bech32 checksum calculated for given segwit program"
	) if ($ver == 0 && $type ne BECH32)
		|| ($ver > 0 && $type ne BECH32M);

	my $bytes = pack('C', $ver) . translate_5to8 $data;
	validate_program($bytes);

	return $bytes;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Bech32 - Bitcoin's Bech32 implementation in Perl

=head1 SYNOPSIS

	# none exported by default
	use Bitcoin::Crypto::Bech32 qw(
		encode_bech32
		decode_bech32
		split_bech32
		encode_segwit
		decode_segwit
	);

	# witness version - a number from 0 to 16, packed into a byte
	my $version = pack "C", 0;

	# human readable part of the address - a string
	my $network_hrp = Bitcoin::Crypto::Network->get->segwit_hrp;

	# handles Bitcoin SegWit adresses
	my $segwit_address = encode_segwit($network_hrp, $version . $pubkeyhash);
	my $data_with_version = decode_segwit($segwit_address);

	# handles custom Bech32 encoding
	my $bech32str = encode_bech32("hello", pack "A*", "world"); # should start with hello1
	my $bytestr = decode_bech32($bech32str);

=head1 DESCRIPTION

Implementation of Bech32 algorithm (BIP-173 and BIP-350 compatible)

The module has a couple of layers of encoding, namely:

=over

=item * base32, which handles the alphabet and 5-to-8 transformation (not exported)

=item * bech32, which handles checksums and human-readable (HRP) parts

=item * segwit, which handles segwit program numbering and validation

=back

For Bech32-encoded SegWit addresses, use I<encode_segwit> and I<decode_segwit>.
For custom uses of Bech32 (not in context of Bitcoin SegWit addresses), use
I<encode_bech32> and I<decode_bech32>.

B<If in doubt, use segwit functions, not bech32 functions!>

=head1 FUNCTIONS

This module is based on Exporter. None of the functions are exported by default. C<:all> tag exists that exports all the functions at once.

=head2 encode_segwit

=head2 decode_segwit

Bech32 encoding / decoding valid for SegWit addresses. Does not validate the human readable part.

These functions also perform segwit program validation, see L<Bitcoin::Crypto::Segwit>.

Encoding takes two arguments which are a human readable part and a byte string.

Decoding takes bech32-encoded string. Returns the entire encoded data along with the segwit program version byte.

=head2 encode_bech32

=head2 decode_bech32

Basic bech32 encoding / decoding.

Encoding takes two arguments which are a human readable part and a byte string.

Decoding takes bech32-encoded string.

B<These methods are not meant to work with Bitcoin SegWit addresses, use encode_segwit and decode_segwit for that instead>

=head2 split_bech32

Splits a bech32-encoded string into human-readable part and data part. Returns a list containing the two.

Performs all validity checks on the input. Dies on every error.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * Bech32InputFormat - input was not suitable for bech32 operations due to invalid format

=item * Bech32InputData - input was parsed with bech32 operations but contained invalid data

=item * Bech32InputChecksum - checksum validation has failed

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Base58>

=item L<Bitcoin::Crypto::Segwit>

=item L<Bitcoin::Crypto::Key::Public>

=back

=cut
