package Bitcoin::Crypto::Bech32;

use Modern::Perl "2010";
use Exporter qw(import);
use Math::BigInt 1.999816 try => 'GMP';

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Segwit qw(validate_program);

our @EXPORT_OK = qw(
	encode_bech32
	decode_bech32
	split_bech32
	encode_segwit
	decode_segwit
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

my $CHECKSUM_SIZE = 6;

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

sub verify_checksum
{
	my ($hrp, $data) = @_;
	return polymod([@{hrp_expand $hrp}, @{to_numarr $data}]) == 1;
}

sub split_bech32
{
	my ($bech32enc) = @_;
	$bech32enc = lc $bech32enc
		if uc $bech32enc eq $bech32enc;

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_format",
		message => "bech32 string too long"
	) if length $bech32enc > 90;

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_format",
		message => "bech32 string contains mixed case"
	) if lc $bech32enc ne $bech32enc;

	my @parts = split "1", $bech32enc;

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_format",
		message => "bech32 separator character missing"
	) if @parts < 2;

	my $data = pop @parts;

	@parts = (join("1", @parts), $data);

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_format",
		message => "incorrect length of bech32 human readable part"
	) if length $parts[0] < 1 || length $parts[0] > 83;

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_format",
		message => "illegal characters in bech32 human readable part"
	) if $parts[0] !~ /^[\x21-\x7e]+$/;

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_format",
		message => "incorrect length of bech32 data part"
	) if length $parts[1] < 6;

	my $chars = join "", @alphabet;
	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_format",
		message => "illegal characters in bech32 data part"
	) if $parts[1] !~ /^[$chars]+$/;

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_checksum",
		message => "incorrect bech32 checksum"
	) unless verify_checksum(@parts);

	return @parts;
}

sub encode_base32
{
	my ($bytes) = @_;

	my @data = unpack "(a5)*", unpack "B*", $bytes;
	my $result = "";
	for my $bitstr (@data) {
		my $pad = 5 - length $bitstr;
		my $num = unpack "C", pack "B*", "000$bitstr" . 0 x $pad;
		$result .= $alphabet[$num];
	}

	return $result;
}

sub decode_base32
{
	my ($encoded) = @_;

	return ""
		unless length $encoded;
	my @enc_values = map { $alphabet_mapped{$_} } split "", $encoded;
	my $bits = unpack "B*", pack "C*", @enc_values;
	$bits = join "", map { substr $_, 3 } unpack "(a8)*", $bits;

	my $length_padded = length $bits;
	my $padding = $length_padded % 8;
	$bits =~ s/0{$padding}$//;

	Bitcoin::Crypto::Exception->raise(
		code => "bech32_input_data",
		message => "incorrrect padding encoded in bech32"
	) if length($bits) % 8 != 0 || length($bits) < $length_padded - 4;

	my @data = unpack "(a8)*", $bits;
	my $result = "";
	for my $bitstr (@data) {
		$result .= pack "B8", $bitstr;
	}
	return $result;
}

sub encode_bech32
{
	my ($hrp, $bytes) = @_;

	my $result = encode_base32($bytes);
	my $checksum = create_checksum($hrp, $result);
	return $hrp . 1 . $result . $checksum;
}

sub encode_segwit
{
	my ($hrp, $bytes) = @_;

	my $version = validate_program($bytes);
	my $result = $alphabet[$version] . encode_base32(substr $bytes, 1);
	my $checksum = create_checksum($hrp, $result);
	return $hrp . 1 . $result . $checksum;
}

sub decode_bech32
{
	my ($hrp, $data) = split_bech32 @_;

	return decode_base32(substr $data, 0, -$CHECKSUM_SIZE);
}

sub decode_segwit
{
	my ($hrp, $data) = split_bech32 @_;

	my $ver = $alphabet_mapped{substr $data, 0, 1};
	my $bytes = pack("C", $ver) . decode_base32(substr $data, 1, -$CHECKSUM_SIZE);
	validate_program($bytes);

	return $bytes;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Bech32 - Bitcoin's Bech32 implementation in Perl (BIP173 compatible)

=head1 SYNOPSIS

	use Bitcoin::Crypto::Bech32 qw(:all);

	my $bech32str = encode_bech32(pack "A*", "hello");
	my $bytestr = decode_bech32($bech32str);

=head1 DESCRIPTION

Implementation of Bech32 algorithm with Math::BigInt (GMP).

=head1 FUNCTIONS

=head2 encode_bech32

=head2 decode_bech32

Basic bech32 encoding / decoding.
Encoding takes one argument which is byte string.
Decoding takes bech32-encoded string and croaks on errors.

=head2 split_bech32

Splits a bech32-encoded string into human-readable part and data part. Returns a list containing the two.
Performs all validity checks on the input. Croaks on every error.

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Key::Public>

=back

=cut
