package Bitcoin::Crypto::Script;

use v5.10;
use strict;
use warnings;
use Moo;
use Crypt::Digest::SHA256 qw(sha256);
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(hash160 hash256 verify_bytestring);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(ArrayRef Str);

use namespace::clean;

has field 'operations' => (
	isa => ArrayRef [Str],
	default => sub { [] },
);

with qw(Bitcoin::Crypto::Role::Network);

# list of significant opcodes from DATA section
our %op_codes = do {
	my @list;
	while (my $line = <DATA>) {
		chomp $line;
		last if $line eq '__END__';

		my @parts = split /\s+/, $line;
		next if @parts == 0;
		die 'too many DATA parts for script opcode'
			if @parts > 2;

		# add key
		push @list, shift @parts;

		# rest of @parts are values
		my ($code) = @parts;
		push @list, {
			code => pack('C', hex $code),
		};
	}

	close DATA;
	@list;
};

sub _get_op_code
{
	my ($context, $op_code) = @_;
	if ($op_code =~ /\AOP_(.+)/) {
		$op_code = $1;
		return $op_codes{$op_code}{code};
	}
	elsif ($op_code =~ /\A[0-9]+\z/ && $op_code >= 1 && $op_code <= 75) {

		# standard data push - 0x01 up to 0x4b
		return pack('C', 0x00 + $op_code);
	}
	else {
		Bitcoin::Crypto::Exception::ScriptOpcode->raise(
			defined $op_code ? "unknown opcode $op_code" : 'undefined opcode variable'
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
		'empty data variable'
	) unless $len;

	if ($bytes =~ /[\x00-\x10]/ && $len == 1) {
		my $num = unpack 'C', $bytes;
		$self->add_operation("OP_$num");
	}
	else {
		if ($len <= 75) {
			$self->add_operation($len);
		}
		elsif ($len < (2 << 7)) {
			$self->add_operation('OP_PUSHDATA1')
				->add_raw(pack 'C', $len);
		}
		elsif ($len < (2 << 15)) {
			$self->add_operation('OP_PUSHDATA2')
				->add_raw(pack 'v', $len);
		}
		elsif (Bitcoin::Crypto::Config::is_32bit || $len < (2 << 31)) {
			$self->add_operation('OP_PUSHDATA4')
				->add_raw(pack 'V', $len);
		}
		else {
			Bitcoin::Crypto::Exception::ScriptPush->raise(
				'too much data to push onto stack in one operation'
			);
		}
		$self->add_raw($bytes);
	}
	return $self;
}

sub get_script
{
	my ($self) = @_;
	return join '', @{$self->operations};
}

sub get_script_hash
{
	my ($self) = @_;
	return hash160($self->get_script);
}

sub witness_program
{
	my ($self) = @_;

	return pack('C', Bitcoin::Crypto::Config::witness_version) . sha256($self->get_script);
}

sub get_legacy_address
{
	my ($self) = @_;
	return encode_base58check($self->network->p2sh_byte . $self->get_script_hash);
}

sub get_compat_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program->add_operation('OP_' . Bitcoin::Crypto::Config::witness_version)
		->push_bytes(sha256($self->get_script));
	return $program->get_legacy_address;
}

sub get_segwit_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	return encode_segwit($self->network->segwit_hrp, $self->witness_program);
}

1;

__DATA__

0                    00
FALSE                00
PUSHDATA1            4c
PUSHDATA2            4d
PUSHDATA4            4e
1NEGATE              4f
RESERVED             50
TRUE                 51
1                    51
2                    52
3                    53
4                    54
5                    55
6                    56
7                    57
8                    58
9                    59
10                   5a
11                   5b
12                   5c
13                   5d
14                   5e
15                   5f
16                   60
NOP                  61
VER                  62
IF                   63
NOTIF                64
VERIF                65
VERNOTIF             66
ELSE                 67
ENDIF                68
VERIFY               69
RETURN               6a
TOALTSTACK           6b
FROMALTSTACK         6c
2DROP                6d
2DUP                 6e
3DUP                 6f
2OVER                70
2ROT                 71
2SWAP                72
IFDUP                73
DEPTH                74
DROP                 75
DUP                  76
NIP                  77
OVER                 78
PICK                 79
ROLL                 7a
ROT                  7b
SWAP                 7c
TUCK                 7d
SIZE                 82
EQUAL                87
EQUALVERIFY          88
RESERVED1            89
RESERVED2            8a
1ADD                 8b
1SUB                 8c
NEGATE               8f
ABS                  90
NOT                  91
ONOTEQUAL            92
ADD                  93
SUB                  94
BOOLAND              9a
BOOLOR               9b
NUMEQUAL             9c
NUMEQUALVERIFY       9d
NUMNOTEQUAL          9e
LESSTHAN             9f
GREATERTHAN          a0
LESSTHANOREQUAL      a1
GREATERTHANOREQUAL   a2
MIN                  a3
MAX                  a4
WITHIN               a5
RIPEMD160            a6
SHA1                 a7
SHA256               a8
HASH160              a9
HASH256              aa
CODESEPARATOR        ab
CHECKSIG             ac
CHECKSIGVERIFY       ad
CHECKMULTISIG        ae
CHECKMULTISIGVERIFY  af
CHECKLOCKTIMEVERFIY  b1
CHECKSEQUENCEVERIFY  b2

__END__
=head1 NAME

Bitcoin::Crypto::Script - Bitcoin script representations

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script;

	my $script = Bitcoin::Crypto::Script->new
		->add_operation('OP_1')
		->add_operation('OP_TRUE')
		->add_operation('OP_EQUAL');

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

	$script_object = $class->new()

A constructor. Returns new script instance.

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

For example, running C<$script->push_bytes("\x03")> will have the same effect as C<$script->add_operation('OP_3')>.

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

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Network>

=back

=cut

