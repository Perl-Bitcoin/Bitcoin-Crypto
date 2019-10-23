package Bitcoin::Crypto::Script;

use Modern::Perl "2010";
use Moo;
use MooX::Types::MooseLike::Base qw(ArrayRef Str);

use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(hash160 hash256);
use Bitcoin::Crypto::Exception;

with "Bitcoin::Crypto::Role::Network";

# list of significant opcodes
my %op_codes = (
	0 => {
		code => "\x00",
		func => sub {
			my ($stack, $ops) = @_;

			push @$stack, 0x00;
		}
	},
	FALSE => {
		code => "\x00",
		func => sub {
			my ($stack, $ops) = @_;

			push @$stack, 0x00;
		}
	},
	PUSHDATA1 => {
		code => "\x4c",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	PUSHDATA2 => {
		code => "\x4d",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	PUSHDATA4 => {
		code => "\x4e",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"1NEGATE" => {
		code => "\x4f",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	RESERVED => {
		code => "\x50",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	TRUE => {
		code => "\x51",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NOP => {
		code => "\x61",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	VER => {
		code => "\x62",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	IF => {
		code => "\x63",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NOTIF => {
		code => "\x64",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	VERIF => {
		code => "\x65",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	VERNOTIF => {
		code => "\x66",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	ELSE => {
		code => "\x67",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	ENDIF => {
		code => "\x68",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	VERIFY => {
		code => "\x69",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	RETURN => {
		code => "\x6a",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	TOALTSTACK => {
		code => "\x6b",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	FROMALTSTACK => {
		code => "\x6c",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"2DROP" => {
		code => "\x6d",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"2DUP" => {
		code => "\x6e",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"3DUP" => {
		code => "\x6f",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"2OVER" => {
		code => "\x70",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"2ROT" => {
		code => "\x71",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"2SWAP" => {
		code => "\x72",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	IFDUP => {
		code => "\x73",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	DEPTH => {
		code => "\x74",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	DROP => {
		code => "\x75",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	DUP => {
		code => "\x76",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NIP => {
		code => "\x77",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	OVER => {
		code => "\x78",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	PICK => {
		code => "\x79",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	ROLL => {
		code => "\x7a",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	ROT => {
		code => "\x7b",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	SWAP => {
		code => "\x7c",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	TUCK => {
		code => "\x7d",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	SIZE => {
		code => "\x82",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	EQUAL => {
		code => "\x87",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	EQUALVERIFY => {
		code => "\x88",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	RESERVED1 => {
		code => "\x89",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	RESERVED2 => {
		code => "\x8a",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"1ADD" => {
		code => "\x8b",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	"1SUB" => {
		code => "\x8c",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NEGATE => {
		code => "\x8f",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	ABS => {
		code => "\x90",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NOT => {
		code => "\x91",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	ONOTEQUAL => {
		code => "\x92",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	ADD => {
		code => "\x93",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	SUB => {
		code => "\x94",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	BOOLAND => {
		code => "\x9a",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	BOOLOR => {
		code => "\x9b",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NUMEQUAL => {
		code => "\x9c",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NUMEQUALVERIFY => {
		code => "\x9d",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	NUMNOTEQUAL => {
		code => "\x9e",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	LESSTHAN => {
		code => "\x9f",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	GREATERTHAN => {
		code => "\xa0",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	LESSTHANOREQUAL => {
		code => "\xa1",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	GREATERTHANOREQUAL => {
		code => "\xa2",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	MIN => {
		code => "\xa3",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	MAX => {
		code => "\xa4",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	WITHIN => {
		code => "\xa5",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	RIPEMD160 => {
		code => "\xa6",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	SHA1 => {
		code => "\xa7",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	SHA256 => {
		code => "\xa8",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	HASH160 => {
		code => "\xa9",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	HASH256 => {
		code => "\xaa",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	CODESEPARATOR => {
		code => "\xab",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	CHECKSIG => {
		code => "\xac",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	CHECKSIGVERIFY => {
		code => "\xad",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	CHECKMULTISIG => {
		code => "\xae",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	CHECKMULTISIGVERIFY => {
		code => "\xaf",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	CHECKLOCKTIMEVERFIY => {
		code => "\xb1",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
	CHECKSEQUENCEVERIFY => {
		code => "\xb2",
		func => sub {
			my ($stack, $ops) = @_;
			# TODO
		}
	},
);

has "operations" => (
	is => "rw",
	isa => ArrayRef[Str],
	default => sub { [] },
);

sub get_op_code
{
	my ($context, $op_code) = @_;
	if ($op_code =~ /^OP_(.+)/) {
		$op_code = $1;

		if (!defined $op_codes{$op_code} && $op_code =~ /^[0-9]+$/ && $op_code >= 2 && $op_code <= 16) {
			# OP_N - starts with 0x52, up to 0x60
			return pack("C", 0x52 + $op_code);
		}
		return $op_codes{$op_code}{code};
	} elsif ($op_code =~ /^[0-9]+$/ && $op_code >= 1 && $op_code <= 75) {
		# standard data push - 0x01 up to 0x4b
		return pack("C", 0x00 + $op_code);
	} else {
		Bitcoin::Crypto::Exception->raise(
			code => "script_opcode",
			message => "unknown opcode $op_code"
		);
	}
}

sub push_raw
{
	my ($self, $bytes) = @_;
	push @{$self->operations}, $bytes;
	return $self;
}

sub add_operation
{
	my ($self, $op_code) = @_;
	my $val = $self->get_op_code($op_code);
	$self->push_raw($val);
	return $self;
}

sub push_bytes
{
	my ($self, $bytes) = @_;
	my $len = length $bytes;
	if ($bytes =~ /[\x00-\x16]/ && $len == 1) {
		my $num = unpack "C", $bytes;
		$self->add_operation("OP_$num");
	} else {
		if ($len <= 75) {
			$self->add_operation($len);
		} elsif ($len < (2 << 7)) {
			$self->add_operation("PUSHDATA1")
				->push_raw(pack "C", $len);
		} elsif ($len < (2 << 15)) {
			$self->add_operation("PUSHDATA2")
				->push_raw(pack "S", $len);
		} elsif ($len < (2 << 31)) {
			$self->add_operation("PUSHDATA4")
				->push_raw(pack "L", $len);
		} else {
			Bitcoin::Crypto::Exception->raise(
				code => "script_push",
				message => "too much data to push onto stack in one operation"
			);
		}
		$self->push_raw($bytes);
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
	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program->add_operation($config{witness_version});
	$program->push_bytes(hash256($self->get_script));
	return $program->get_script;
}

sub get_legacy_address
{
	my ($self) = @_;
	return encode_base58check($self->network->{p2sh_byte} . $self->get_script_hash);
}

sub get_compat_address
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program->add_operation("OP_" . $config{witness_version})
		->push_bytes(hash256($self->get_script));
	return $program->get_legacy_address;
}

sub get_segwit_address
{
	my ($self) = @_;

	return encode_bech32($self->network->{segwit_hrp}, $self->witness_program);
}

1;
__END__
=head1 NAME

Bitcoin::Crypto::Script - class for Bitcoin public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::PublicKey;

	# verify signature (it has to be byte string, see perlpacktut)

	$pub->verify_message("Hello world", $sig);

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

=head2 from_bytes

	sig: from_bytes($class, $data)
Use this method to create a PublicKey instance from a byte string.
Data $data will be used as a private key entropy.
Returns class instance.

=head2 new

	sig: new($class, $data)
This works exactly the same as from_bytes

=head2 to_bytes

	sig: to_bytes($self)
Does the opposite of from_bytes on a target object

=head2 from_hex

	sig: from_hex($class, $hex)
Use this method to create a PrivateKey instance from a hexadecimal number.
Number $hex will be used as a private key entropy.
Returns class instance.

=head2 to_hex

	sig: to_hex($self)
Does the opposite of from_hex on a target object

=head2 set_compressed

	sig: set_compressed($self, $val)
Change key's compression state to $val (1/0). This will change the address.
If $val is omitted it is set to 1.
Returns current key instance.

=head2 set_network

	sig: set_network($self, $val)
Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. This will change
the address.
Returns current key instance.

=head2 verify_message

	sig: verify_message($self, $message, $signature, $algo = "sha256")
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
