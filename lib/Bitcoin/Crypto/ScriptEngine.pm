package Bitcoin::Crypto::ScriptEngine;

use v5.10; use warnings;
use Exporter qw(import);
use Crypt::Digest::SHA256 qw(sha256);
use List::Util qw(reduce);

use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Helpers qw(hash160 hash256);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto;

our $VERSION = Bitcoin::Crypto->VERSION;
our @EXPORT_OK = qw(
	get_opcode
);

use constant PER_BYTE => (2 << 7);
use constant STACK_BYTE_VECTOR_LIMIT => 520;

sub ex_err
{
	Bitcoin::Crypto::Exception::ScriptExecution->raise(
		shift
	) if shift;
}

sub pushdata
{
	my ($size, $stack, $ops) = @_;

	ex_err @$ops < $size, "not enough data on the operator stack";
	my $count = from_script_number(splice @$ops, 0, $size);

	ex_err @$ops < $count, "not enough data on the operator stack";
	ex_err $count > STACK_BYTE_VECTOR_LIMIT, "too much data to push onto the stack, the byte limit is " . STACK_BYTE_VECTOR_LIMIT;

	my @data = splice @$ops, 0, $count;
	push @$stack, join "", @data;
}

sub pop_stack
{
	my ($stack, $count) = @_;
	$count //= 1;
	ex_err @$stack < $count, "not enough data on stack";
	return map { pop @$stack } 1 .. $count;
}

sub from_script_number
{
	my ($byte_number) = @_;

	my $byte_count = length $byte_number;
	ex_err $byte_count > 4, "numbers on stack need to fit in 4 bytes";

	# we decode ourselves byte by byte to allow 3 byte integers
	my @bytes = unpack "C*", $byte_number;

	# on 32-bit machines, this will be required to handle the full range of numbers
	use bigint lib => 'LTM';

	# decoding the number as little endian
	my $current_byte = 1;
	my $number = reduce {
		$a + $b * PER_BYTE ** $current_byte++
		} @bytes;

	# signed magnitude method of encoding signed numbers
	my $negative_threshold = 2 << ($byte_count * 8 - 2);
	if ($number >= $negative_threshold) {
		$number = -1 * ($number - $negative_threshold);
	}

	return $number;
}

sub to_script_number
{
	my ($number) = @_;

	# on 32-bit machines, this will be required to handle the full range of numbers
	use bigint lib => 'LTM';

	# check how many bytes we need
	# (do not constrain to 4 bytes - only checked during decoding)
	my $required_length = 1;
	while (abs $number >= (2 << ($required_length * 8 - 2)) - 1) {
		$required_length += 1;
	}

	# signed integer encoding
	if ($number < 0) {
		my $negative_threshold = 2 << ($required_length * 8 - 2);
		$number = abs($number) + $negative_threshold;
	}

	# transform to individual byte values - little endian
	my @bytes = map {
		int($number / PER_BYTE ** $_) % PER_BYTE
		} 0 .. $required_length - 1;

	return pack "C*", @bytes;
}

# list of significant opcodes
our %opcodes = (
	FALSE => {
		code => "\x00",
		func => sub {
			my ($stack, $ops) = @_;

			push @$stack, "\x00";
		}
	},
	PUSHDATA1 => {
		code => "\x4c",
		func => sub {
			pushdata 1, @_;
		}
	},
	PUSHDATA2 => {
		code => "\x4d",
		func => sub {
			pushdata 2, @_;
		}
	},
	PUSHDATA4 => {
		code => "\x4e",
		func => sub {
			pushdata 4, @_;
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

			my $a = from_script_number pop_stack $stack;
			$a = -$a;
			push @$stack, to_script_number $a;
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

			my ($a, $b) = map { from_script_number $_ }
				pop_stack $stack, 2;
			push @$stack, to_script_number $a + $b;
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

			my $data = pop_stack $stack;
			push @$stack, sha256($data);
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

# Standard numeric codes - 2 to 16 (start with 0x50)
for my $numeric_code (2 .. 16) {
	$opcodes{$numeric_code} = {
		code => pack("C", 0x50 + $numeric_code),
		func => sub {
			my ($stack, $ops) = @_;
			push @$stack, to_script_number($numeric_code);
		},
	};
}

# 0 and 1 - references FALSE and TRUE
$opcodes{0} = $opcodes{FALSE};
$opcodes{1} = $opcodes{TRUE};

my %opcodes_reverse = map {
		$opcodes{$_}{code} => { %{$opcodes{$_}}, name => $_ }
	} keys %opcodes;

sub get_opcode
{
	my ($op_code) = @_;
	if ($op_code =~ /^OP_(.+)/) {
		$op_code = $1;
		return $opcodes{$op_code};
	}
	elsif ($op_code =~ /^[0-9]+$/ && $op_code >= 1 && $op_code <= 75) {

		# standard data push - 0x01 up to 0x4b
		# (these are not real opcodes)
		return {
			"code" => pack("C", 0x00 + $op_code),
			"func" => sub {
				my ($stack, $ops) = @_;

				ex_err @$ops < $op_code, "not enough data on the operator stack";
				my @data = splice @$ops, 0, $op_code;

				push @$stack, join "", @data;
			},
		};
	}
	else {
		Bitcoin::Crypto::Exception::ScriptOpcode->raise(
			defined $op_code ? "unknown opcode $op_code" : "undefined opcode variable"
		);
	}
}

sub get_reverse_opcode
{
}

sub debug_script
{
	my ($script) = @_;

	my @ops = split //, $script;
	my $stack = [];

	return sub {
		my $op = shift @ops;
		return unless defined $op;

		my $opcode = $opcodes_reverse{$op} // get_opcode(unpack "C", $op);
		Bitcoin::Crypto::Exception::ScriptOpcode->raise(
			"unknown operation with code " . unpack "H*", $op
		) unless defined $opcode;

		$opcode->{func}($stack, \@ops);

		return {
			finished => @ops == 0,
			last_op => $opcode,
			stack => $stack,
		};
	};
}

sub execute_script
{
	my $handle = debug_script @_;

	my $data = $handle->();
	while (!$data->{finished}) {
		$data = $handle->();
	}

	return $data->{stack};
}


1;
