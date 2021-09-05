package Bitcoin::Crypto::Script;

our $VERSION = "1.000";

use v5.10;
use warnings;
use Moo;
use Types::Standard qw(ArrayRef Str);
use Crypt::Digest::SHA256 qw(sha256);

use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(hash160 hash256 verify_bytestring);
use Bitcoin::Crypto::Exception;

use namespace::clean;

with "Bitcoin::Crypto::Role::Network";

# list of significant opcodes
our %op_codes = (
	FALSE => {
		code => "\x00",
	},
	PUSHDATA1 => {
		code => "\x4c",
	},
	PUSHDATA2 => {
		code => "\x4d",
	},
	PUSHDATA4 => {
		code => "\x4e",
	},
	"1NEGATE" => {
		code => "\x4f",
	},
	RESERVED => {
		code => "\x50",
	},
	TRUE => {
		code => "\x51",
	},
	NOP => {
		code => "\x61",
	},
	VER => {
		code => "\x62",
	},
	IF => {
		code => "\x63",
	},
	NOTIF => {
		code => "\x64",
	},
	VERIF => {
		code => "\x65",
	},
	VERNOTIF => {
		code => "\x66",
	},
	ELSE => {
		code => "\x67",
	},
	ENDIF => {
		code => "\x68",
	},
	VERIFY => {
		code => "\x69",
	},
	RETURN => {
		code => "\x6a",
	},
	TOALTSTACK => {
		code => "\x6b",
	},
	FROMALTSTACK => {
		code => "\x6c",
	},
	"2DROP" => {
		code => "\x6d",
	},
	"2DUP" => {
		code => "\x6e",
	},
	"3DUP" => {
		code => "\x6f",
	},
	"2OVER" => {
		code => "\x70",
	},
	"2ROT" => {
		code => "\x71",
	},
	"2SWAP" => {
		code => "\x72",
	},
	IFDUP => {
		code => "\x73",
	},
	DEPTH => {
		code => "\x74",
	},
	DROP => {
		code => "\x75",
	},
	DUP => {
		code => "\x76",
	},
	NIP => {
		code => "\x77",
	},
	OVER => {
		code => "\x78",
	},
	PICK => {
		code => "\x79",
	},
	ROLL => {
		code => "\x7a",
	},
	ROT => {
		code => "\x7b",
	},
	SWAP => {
		code => "\x7c",
	},
	TUCK => {
		code => "\x7d",
	},
	SIZE => {
		code => "\x82",
	},
	EQUAL => {
		code => "\x87",
	},
	EQUALVERIFY => {
		code => "\x88",
	},
	RESERVED1 => {
		code => "\x89",
	},
	RESERVED2 => {
		code => "\x8a",
	},
	"1ADD" => {
		code => "\x8b",
	},
	"1SUB" => {
		code => "\x8c",
	},
	NEGATE => {
		code => "\x8f",
	},
	ABS => {
		code => "\x90",
	},
	NOT => {
		code => "\x91",
	},
	ONOTEQUAL => {
		code => "\x92",
	},
	ADD => {
		code => "\x93",
	},
	SUB => {
		code => "\x94",
	},
	BOOLAND => {
		code => "\x9a",
	},
	BOOLOR => {
		code => "\x9b",
	},
	NUMEQUAL => {
		code => "\x9c",
	},
	NUMEQUALVERIFY => {
		code => "\x9d",
	},
	NUMNOTEQUAL => {
		code => "\x9e",
	},
	LESSTHAN => {
		code => "\x9f",
	},
	GREATERTHAN => {
		code => "\xa0",
	},
	LESSTHANOREQUAL => {
		code => "\xa1",
	},
	GREATERTHANOREQUAL => {
		code => "\xa2",
	},
	MIN => {
		code => "\xa3",
	},
	MAX => {
		code => "\xa4",
	},
	WITHIN => {
		code => "\xa5",
	},
	RIPEMD160 => {
		code => "\xa6",
	},
	SHA1 => {
		code => "\xa7",
	},
	SHA256 => {
		code => "\xa8",
	},
	HASH160 => {
		code => "\xa9",
	},
	HASH256 => {
		code => "\xaa",
	},
	CODESEPARATOR => {
		code => "\xab",
	},
	CHECKSIG => {
		code => "\xac",
	},
	CHECKSIGVERIFY => {
		code => "\xad",
	},
	CHECKMULTISIG => {
		code => "\xae",
	},
	CHECKMULTISIGVERIFY => {
		code => "\xaf",
	},
	CHECKLOCKTIMEVERFIY => {
		code => "\xb1",
	},
	CHECKSEQUENCEVERIFY => {
		code => "\xb2",
	},
);

$op_codes{0} = $op_codes{FALSE};
$op_codes{1} = $op_codes{TRUE};

for (2 .. 16) {

	# OP_N - starts with 0x52, up to 0x60
	$op_codes{$_} = {
		code => pack("C", 0x50 + $_),
	};
}

has "operations" => (
	is => "rw",
	isa => ArrayRef [Str],
	default => sub { [] },
);

sub _get_op_code
{
	my ($context, $op_code) = @_;
	if ($op_code =~ /^OP_(.+)/) {
		$op_code = $1;
		return $op_codes{$op_code}{code};
	}
	elsif ($op_code =~ /^[0-9]+$/ && $op_code >= 1 && $op_code <= 75) {

		# standard data push - 0x01 up to 0x4b
		return pack("C", 0x00 + $op_code);
	}
	else {
		Bitcoin::Crypto::Exception::ScriptOpcode->raise(
			defined $op_code ? "unknown opcode $op_code" : "undefined opcode variable"
		);
	}
}

sub add_raw
{
	my ($self, $bytes) = @_;
	verify_bytestring($bytes);

	push @{$self->operations}, $bytes;
	return $self;
}

sub add_operation
{
	my ($self, $op_code) = @_;
	my $val = $self->_get_op_code($op_code);
	$self->add_raw($val);
	return $self;
}

sub push_bytes
{
	my ($self, $bytes) = @_;
	verify_bytestring($bytes);

	my $len = length $bytes;
	Bitcoin::Crypto::Exception::ScriptPush->raise(
		"empty data variable"
	) unless $len;

	if ($bytes =~ /[\x00-\x10]/ && $len == 1) {
		my $num = unpack "C", $bytes;
		$self->add_operation("OP_$num");
	}
	else {
		use bigint;
		if ($len <= 75) {
			$self->add_operation($len);
		}
		elsif ($len < (2 << 7)) {
			$self->add_operation("OP_PUSHDATA1")
				->add_raw(pack "C", $len);
		}
		elsif ($len < (2 << 15)) {
			$self->add_operation("OP_PUSHDATA2")
				->add_raw(pack "S", $len);
		}
		elsif ($len < (2 << 31)) {
			$self->add_operation("OP_PUSHDATA4")
				->add_raw(pack "L", $len);
		}
		else {
			Bitcoin::Crypto::Exception::ScriptPush->raise(
				"too much data to push onto stack in one operation"
			);
		}
		$self->add_raw($bytes);
	}
	return $self;
}

sub get_script
{
	my ($self) = @_;
	return join "", @{$self->operations};
}

sub get_script_hash
{
	my ($self) = @_;
	return hash160($self->get_script);
}

sub witness_program
{
	my ($self) = @_;

	return pack("C", Bitcoin::Crypto::Config::witness_version) . sha256($self->get_script);
}

sub get_legacy_address
{
	my ($self) = @_;
	return encode_base58check($self->network->p2sh_byte . $self->get_script_hash);
}

sub get_compat_address
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program->add_operation("OP_" . Bitcoin::Crypto::Config::witness_version)
		->push_bytes(sha256($self->get_script));
	return $program->get_legacy_address;
}

sub get_segwit_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"no segwit_hrp found in network configuration"
	) unless defined $self->network->segwit_hrp;

	return encode_segwit($self->network->segwit_hrp, $self->witness_program);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Script - Bitcoin script representations

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script;

	my $script = Bitcoin::Crypto::Script->new
		->add_operation("OP_1")
		->add_operation("OP_TRUE")
		->add_operation("OP_EQUAL");

	# getting serialized script
	my $serialized = $script->get_script();

	# getting address from script (p2wsh)
	my $address = $script->get_segwit_adress();

=head1 DESCRIPTION

This class allows you to create a bitcoin script representations

You can use a script object to:

=over 2

=item * create a script from opcodes

=item * serialize script into byte string

=item * create legacy (p2sh), compat (p2sh(p2wsh)) and segwit (p2wsh) adresses

=back

=head1 METHODS

=head2 new

	$script_object = $class->new($data)

A constructor. Returns new script instance

=head2 add_operation

	$script_object = $object->add_operation($opcode)

Adds a new opcode at the end of a script. Returns the object instance for chaining.

Throws an exception for unknown opcodes.

=head2 add_raw

	$script_object = $object->add_raw($bytes)

Adds C<$bytes> at the end of a script.
Useful when you need a value in a script that shouldn't be pushed to the execution stack, like the first four bytes after C<PUSHDATA4>.

Returns the object instance for chaining.

=head2 push_bytes

	$script_object = $object->push_bytes($bytes)

Pushes C<$bytes> to the execution stack at the end of a script, using a minimal push opcode.

For example, running C<$script->push_bytes("\x03")> will have the same effect as C<$script->add_operation("OP_3")>.

Throws an exception for data exceeding a 4 byte number in length.

Returns the object instance for chaining.

=head2 get_script

	$bytestring = $object->get_script()

Returns a serialized script as byte string.

=head2 get_script_hash

	$bytestring = $object->get_script_hash()

Returns a serialized script parsed with C<HASH160> (ripemd160 of sha256).

=head2 set_network

	$script_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in L<Bitcoin::Crypto::Network> package or an instance of this class.

Returns current object instance.

=head2 get_legacy_address

	$address = $object->get_legacy_address()

Returns string containing Base58Check encoded script hash (p2sh address)

=head2 get_compat_address

	$address = $object->get_compat_address()

Returns string containing Base58Check encoded script hash containing a witness program for compatibility purposes (p2sh(p2wsh) address)

=head2 get_segwit_address

	$address = $object->get_segwit_address()

Returns string containing Bech32 encoded witness program (p2wsh address)

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * ScriptOpcode - unknown opcode was specified

=item * ScriptPush - data pushed to the execution stack is invalid

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::PrivateKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut
