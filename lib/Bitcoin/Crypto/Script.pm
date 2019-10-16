package Bitcoin::Crypto::Script;

use Modern::Perl "2010";
use Moo;
use MooX::Types::MooseLike::Base qw(ArrayRef Str);
use Carp qw(croak);

use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(hash160 hash256);
with "Bitcoin::Crypto::Roles::Network";

# list of significant opcodes
my %op_codes = (
	0 => "\x00",
	FALSE => "\x00",
	PUSHDATA1 => "\x4c",
	PUSHDATA2 => "\x4c",
	PUSHDATA4 => "\x4e",
	"1NEGATE" => "\x4f",
	RESERVED => "\x50",
	TRUE => "\x51",
	NOP => "\x61",
	VER => "\x62",
	IF => "\x63",
	NOTIF => "\x64",
	VERIF => "\x65",
	VERNOTIF => "\x66",
	ELSE => "\x67",
	ENDIF => "\x68",
	VERIFY => "\x69",
	RETURN => "\x6a",
	CHECKLOCKTIMEVERIFY => "\xb1",
	CHECKSEQUENCEVERIFY => "\xb2",
	TOALTSTACK => "\x6b",
	FROMALTSTACK => "\x6c",
	"2DROP" => "\x6d",
	"2DUP" => "\x6e",
	"3DUP" => "\x6f",
	"2OVER" => "\x70",
	"2ROT" => "\x71",
	"2SWAP" => "\x72",
	IFDUP => "\x73",
	DEPTH => "\x74",
	DROP => "\x75",
	DUP => "\x76",
	NIP => "\x77",
	OVER => "\x78",
	PICK => "\x79",
	ROLL => "\x7a",
	ROT => "\x7b",
	SWAP => "\x7c",
	TUCK => "\x7d",
	# CAT => "\x7e",
	# SUBSTR => "\x7f",
	# LEFT => "\x80",
	# RIGHT => "\x81",
	SIZE => "\x82",
	# INVERT => "\x83",
	# AND => "\x84",
	# OR => "\x85",
	# XOR => "\x86",
	EQUAL => "\x87",
	EQUALVERIFY => "\x88",
	RESERVED1 => "\x89",
	RESERVED2 => "\x8a",
	"1ADD" => "\x8b",
	"1SUB" => "\x8c",
	# "2MUL" => "\x8d",
	# "2DIV" => "\x8e",
	NEGATE => "\x8f",
	ABS => "\x90",
	NOT => "\x91",
	ONOTEQUAL => "\x92",
	ADD => "\x93",
	SUB => "\x94",
	# MUL => "\x95",
	# DIV => "\x96",
	# MOD => "\x97",
	# LSHIFT => "\x98",
	# RSHIFT => "\x99",
	BOOLAND => "\x9a",
	BOOLOR => "\x9b",
	NUMEQUAL => "\x9c",
	NUMEQUALVERIFY => "\x9d",
	NUMNOTEQUAL => "\x9e",
	LESSTHAN => "\x9f",
	GREATERTHAN => "\xa0",
	LESSTHANOREQUAL => "\xa1",
	GREATERTHANOREQUAL => "\xa2",
	MIN => "\xa3",
	MAX => "\xa4",
	WITHIN => "\xa5",
	RIPEMD160 => "\xa6",
	SHA1 => "\xa7",
	SHA256 => "\xa8",
	HASH160 => "\xa9",
	HASH256 => "\xaa",
	CODESEPARATOR => "\xab",
	CHECKSIG => "\xac",
	CHECKSIGVERIFY => "\xad",
	CHECKMULTISIG => "\xae",
	CHECKMULTISIGVERIFY => "\xaf",
	CHECKLOCKTIMEVERFIY => "\xb1",
	CHECKSEQUENCEVERIFY => "\xb2",
	# PUBKEYHASH => "\xfd",
	# PUBKEY => "\xfe",
	# INVALIDOPCODE => "\xff",
);

has "operations" => (
	is => "rw",
	isa => ArrayRef[Str],
	default => sub { [] },
);

sub getOpCode
{
	my ($context, $op_code) = @_;
	if ($op_code =~ /^OP_(.+)/) {
		$op_code = $1;

		if (!defined $op_codes{$op_code} && $op_code =~ /^[0-9]+$/ && $op_code >= 2 && $op_code <= 16) {
			# OP_N - starts with 0x52, up to 0x60
			return pack("C", 0x52 + $op_code);
		}
		return $op_codes{$op_code};
	} elsif ($op_code =~ /^[0-9]+$/ && $op_code >= 1 && $op_code <= 75) {
		# standard data push - 0x01 up to 0x4b
		return pack("C", 0x00 + $op_code);
	} else {
		croak {reason => "script_opcode", message => "unknown opcode $op_code"};
	}
}

sub pushRaw
{
	my ($self, $bytes) = @_;
	push @{$self->operations}, $bytes;
	return $self;
}

sub addOperation
{
	my ($self, $op_code) = @_;
	my $val = $self->getOpCode($op_code);
	$self->pushRaw($val);
	return $self;
}

sub pushBytes
{
	my ($self, $bytes) = @_;
	my $len = length $bytes;
	if ($bytes =~ /[\x00-\x16]/ && $len == 1) {
		my $num = unpack "C", $bytes;
		$self->addOperation("OP_$num");
	} else {
		if ($len <= 75) {
			$self->addOperation($len);
		} elsif ($len < (2 << 7)) {
			$self->addOperation("PUSHDATA1")
				->pushRaw(pack "C", $len);
		} elsif ($len < (2 << 15)) {
			$self->addOperation("PUSHDATA2")
				->pushRaw(pack "S", $len);
		} elsif ($len < (2 << 31)) {
			$self->addOperation("PUSHDATA4")
				->pushRaw(pack "L", $len);
		} else {
			croak {reason => "script_push", message => "too much data to push onto stack in one operation"};
		}
		$self->pushRaw($bytes);
	}
	return $self;
}

sub getScript
{
	my ($self) = @_;
	return join "", @{$self->operations};
}

sub getScriptHash
{
	my ($self) = @_;
	return hash160($self->getScript);
}

sub witnessProgram
{
	my ($self) = @_;
	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program->addOperation($config{witness_version});
	$program->pushBytes(hash256($self->getScript));
	return $program->getScript;
}

sub getLegacyAddress
{
	my ($self) = @_;
	return encode_base58check($self->network->{p2sh_byte} . $self->getScriptHash);
}

sub getCompatAddress
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program->addOperation("OP_" . $config{witness_version})
		->pushBytes(hash256($self->getScript));
	return $program->getLegacyAddress;
}

sub getSegwitAddress
{
	my ($self) = @_;

	return encode_bech32($self->network->{segwit_hrp}, $self->witnessProgram);
}

1;
__END__
=head1 NAME

Bitcoin::Crypto::Script - class for Bitcoin public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::PublicKey;

	# verify signature (it has to be byte string, see perlpacktut)

	$pub->verifyMessage("Hello world", $sig);

	# getting address from public key (p2pkh)

	my $address = $pub->getAddress();

=head1 DESCRIPTION

This class allows you to create a public key instance.

You can use a public key to:

=over 2

=item * verify messages

=item * create p2pkh address

=back

=head1 METHODS

=head2 fromBytes

	sig: fromBytes($class, $data)
Use this method to create a PublicKey instance from a byte string.
Data $data will be used as a private key entropy.
Returns class instance.

=head2 new

	sig: new($class, $data)
This works exactly the same as fromBytes

=head2 toBytes

	sig: toBytes($self)
Does the opposite of fromBytes on a target object

=head2 fromHex

	sig: fromHex($class, $hex)
Use this method to create a PrivateKey instance from a hexadecimal number.
Number $hex will be used as a private key entropy.
Returns class instance.

=head2 toHex

	sig: toHex($self)
Does the opposite of fromHex on a target object

=head2 setCompressed

	sig: setCompressed($self, $val)
Change key's compression state to $val (1/0). This will change the address.
If $val is omitted it is set to 1.
Returns current key instance.

=head2 setNetwork

	sig: setNetwork($self, $val)
Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. This will change
the address.
Returns current key instance.

=head2 verifyMessage

	sig: verifyMessage($self, $message, $signature, $algo = "sha256")
Verifies $signature against digest of $message (with $algo digest algorithm)
using private key.
$algo must be available in Digest package.
Returns boolean.

=head2 getAddress

	sig: getAddress($self)
Returns string containing Base58Check encoded public key hash (p2pkh address)

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::PrivateKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut
