package Bitcoin::Crypto::Script::Opcode;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Str StrLength CodeRef);

use namespace::clean;

has param 'name' => (
	isa => Str,
);

has param 'code' => (
	isa => StrLength[1, 1],
);

has option 'runner' => (
	isa => CodeRef,
	predicate => 'implemented',
);

sub execute
{
	my ($self, @args) = @_;

	die $self->name . ' is not implemented'
		unless $self->implemented;

	return $self->runner->(@args);
}

my %opcodes = (
	OP_0 => {
		code => "\x00",
		runner => sub {
			my $runner = shift;

			push @{$runner->stack}, "\x00";
		},
	},
	OP_PUSHDATA1 => {
		code => "\x4c",
		runner => sub {
			my ($runner, $bytes) = @_;

			push @{$runner->stack}, $bytes;
		},
	},
	OP_PUSHDATA2 => {
		code => "\x4d",
		# see runner below
	},
	OP_PUSHDATA4 => {
		code => "\x4e",
		# see runner below
	},
	OP_1NEGATE => {
		code => "\x4f",
		runner => sub {
			my $runner = shift;

			push @{$runner->stack}, $runner->_fromint(-1);
		},
	},
	OP_RESERVED => {
		code => "\x50",
	},
	OP_NOP => {
		code => "\x61",
		runner => sub {
			# does nothing
		},
	},
	OP_VER => {
		code => "\x62",
	},
	OP_IF => {
		code => "\x63",
		runner => sub {
			my ($runner, $else_pos, $endif_pos) = @_;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			if ($runner->_tobool(pop @$stack)) {
				# continue execution
			}
			else {
				if (defined $else_pos) {
					$runner->_set_pos($else_pos);
				}
				else {
					$runner->_set_pos($endif_pos);
				}
			}
		},
	},
	OP_NOTIF => {
		code => "\x64",
		# see runner below
	},
	OP_VERIF => {
		code => "\x65",
	},
	OP_VERNOTIF => {
		code => "\x66",
	},
	OP_ELSE => {
		code => "\x67",
		# should only get called when IF branch ops are depleted
		runner => sub {
			my ($runner, $endif_pos) = @_;

			$runner->_set_pos($endif_pos);
		},
	},
	OP_ENDIF => {
		code => "\x68",
		# should only get called when IF or ELSE branch ops are depleted
		runner => sub {
			# nothing to do here, will step to the next op
		},
	},
	OP_VERIFY => {
		code => "\x69",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless $runner->_tobool($stack->[-1]);

			# pop later so that problematic value can be seen on the stack
			pop @$stack;
		},
	},
	OP_RETURN => {
		code => "\x6a",
		runner => sub {
			my $runner = shift;

			die;
		},
	},
	OP_TOALTSTACK => {
		code => "\x6b",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @{$runner->alt_stack}, pop @$stack;
		},
	},
	OP_FROMALTSTACK => {
		code => "\x6c",
		runner => sub {
			my $runner = shift;
			my $alt = $runner->alt_stack;

			die unless @$alt >= 1;
			push @{$runner->stack}, pop @$alt;
		},
	},
	OP_2DROP => {
		code => "\x6d",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			splice @$stack, -2, 2;
		},
	},
	OP_2DUP => {
		code => "\x6e",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, @$stack[-2, -1];
		},
	},
	OP_3DUP => {
		code => "\x6f",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 3;
			push @$stack, @$stack[-3, -2, -1];
		},
	},
	OP_2OVER => {
		code => "\x70",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 4;
			push @$stack, @$stack[-4, -3];
		},
	},
	OP_2ROT => {
		code => "\x71",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 6;
			push @$stack, splice @$stack, -6, 2;
		},
	},
	OP_2SWAP => {
		code => "\x72",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 4;
			push @$stack, splice @$stack, -4, 2;
		},
	},
	OP_IFDUP => {
		code => "\x73",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			if ($runner->_tobool($stack->[-1])) {
				push @$stack, $stack->[-1];
			}
		},
	},
	OP_DEPTH => {
		code => "\x74",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			push @$stack, $runner->_fromint(scalar @$stack);
		},
	},
	OP_DROP => {
		code => "\x75",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			pop @$stack;
		},
	},
	OP_DUP => {
		code => "\x76",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, $stack->[-1];
		},
	},
	OP_NIP => {
		code => "\x77",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			splice @$stack, -2, 1;
		},
	},
	OP_OVER => {
		code => "\x78",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $stack->[-2];
		},
	},
	OP_PICK => {
		code => "\x79",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;

			my $n = $runner->_toint(pop @$stack);
			die if $n < 0 || $n >= @$stack;

			push @$stack, $stack->[-1 * ($n + 1)];
		},
	},
	OP_ROLL => {
		code => "\x7a",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;

			my $n = $runner->_toint(pop @$stack);
			die if $n < 0 || $n >= @$stack;

			push @$stack, splice @$stack, -1 * ($n + 1), 1;
		},
	},
	OP_ROT => {
		code => "\x7b",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 3;
			push @$stack, splice @$stack, -3, 1;
		},
	},
	OP_SWAP => {
		code => "\x7c",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, splice @$stack, -2, 1;
		},
	},
	OP_TUCK => {
		code => "\x7d",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			splice @$stack, -2, 0, $stack->[-1];
		},
	},
	OP_SIZE => {
		code => "\x82",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, length $stack->[-1];
		},
	},
	OP_EQUAL => {
		code => "\x87",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(pop(@$stack) eq pop(@$stack));
		},
	},
	OP_EQUALVERIFY => {
		code => "\x88",
		# see runner below
	},
	OP_RESERVED1 => {
		code => "\x89",
	},
	OP_RESERVED2 => {
		code => "\x8a",
	},
	OP_1ADD => {
		code => "\x8b",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, $runner->_fromint($runner->_toint(pop @$stack) + 1);
		},
	},
	OP_1SUB => {
		code => "\x8c",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, $runner->_fromint($runner->_toint(pop @$stack) - 1);
		},
	},
	OP_NEGATE => {
		code => "\x8f",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, $runner->_fromint($runner->_toint(pop @$stack) * -1);
		},
	},
	OP_ABS => {
		code => "\x90",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, $runner->_fromint(abs $runner->_toint(pop @$stack));
		},
	},
	OP_NOT => {
		code => "\x91",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, $runner->_frombool($runner->_toint(pop @$stack) == 0);
		},
	},
	OP_ONOTEQUAL => {
		code => "\x92",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, $runner->_frombool($runner->_toint(pop @$stack) != 0);
		},
	},
	OP_ADD => {
		code => "\x93",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_fromint(
				$runner->_toint(pop @$stack)
				+ $runner->_toint(pop @$stack)
			);
		},
	},
	OP_SUB => {
		code => "\x94",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_fromint(
				-1 * $runner->_toint(pop @$stack)
				+ $runner->_toint(pop @$stack)
			);
		},
	},
	OP_BOOLAND => {
		code => "\x9a",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack) != 0
				&& $runner->_toint(pop @$stack) != 0
			);
		},
	},
	OP_BOOLOR => {
		code => "\x9b",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack) != 0
				|| $runner->_toint(pop @$stack) != 0
			);
		},
	},
	OP_NUMEQUAL => {
		code => "\x9c",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack)
				== $runner->_toint(pop @$stack)
			);
		},
	},
	OP_NUMEQUALVERIFY => {
		code => "\x9d",
		# see runner below
	},
	OP_NUMNOTEQUAL => {
		code => "\x9e",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack)
				!= $runner->_toint(pop @$stack)
			);
		},
	},
	OP_LESSTHAN => {
		code => "\x9f",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack)
				> $runner->_toint(pop @$stack)
			);
		},
	},
	OP_GREATERTHAN => {
		code => "\xa0",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack)
				< $runner->_toint(pop @$stack)
			);
		},
	},
	OP_LESSTHANOREQUAL => {
		code => "\xa1",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack)
				>= $runner->_toint(pop @$stack)
			);
		},
	},
	OP_GREATERTHANOREQUAL => {
		code => "\xa2",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			push @$stack, $runner->_frombool(
				$runner->_toint(pop @$stack)
				<= $runner->_toint(pop @$stack)
			);
		},
	},
	OP_MIN => {
		code => "\xa3",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			my ($first, $second) = splice @$stack, -2, 2;
			push @$stack, $runner->_toint($first) < $runner->_toint($second)
				? $first : $second;
		},
	},
	OP_MAX => {
		code => "\xa4",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 2;
			my ($first, $second) = splice @$stack, -2, 2;
			push @$stack, $runner->_toint($first) > $runner->_toint($second)
				? $first : $second;
		},
	},
	OP_WITHIN => {
		code => "\xa5",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 3;
			my ($first, $second, $third) = map { $runner->_toint($_) } splice @$stack, -3, 3;
			push @$stack, $runner->_frombool($first >= $second && $first < $third);
		},
	},
	OP_RIPEMD160 => {
		code => "\xa6",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, ripemd160(pop @$stack);
		},
	},
	OP_SHA1 => {
		code => "\xa7",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, sha1(pop @$stack);
		},
	},
	OP_SHA256 => {
		code => "\xa8",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, sha256(pop @$stack);
		},
	},
	OP_HASH160 => {
		code => "\xa9",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, hash160(pop @$stack);
		},
	},
	OP_HASH256 => {
		code => "\xaa",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			die unless @$stack >= 1;
			push @$stack, hash256(pop @$stack);
		},
	},
	OP_CODESEPARATOR => {
		code => "\xab",
		runner => sub {
			my $runner = shift;
		},
	},
	OP_CHECKSIG => {
		code => "\xac",
		runner => sub {
			my $runner = shift;
		},
	},
	OP_CHECKSIGVERIFY => {
		code => "\xad",
		# see runner below
	},
	OP_CHECKMULTISIG => {
		code => "\xae",
		runner => sub {
			my $runner = shift;
		},
	},
	OP_CHECKMULTISIGVERIFY => {
		code => "\xaf",
		# see runner below
	},
	OP_CHECKLOCKTIMEVERFIY => {
		code => "\xb1",
		runner => sub {
			my $runner = shift;
		},
	},
	OP_CHECKSEQUENCEVERIFY => {
		code => "\xb2",
		runner => sub {
			my $runner = shift;
		},
	},
);

for my $num (1 .. 16) {
	$opcodes{"OP_$num"} = {
		code => chr(0x50 + $num),
		runner => sub {
			my $runner = shift;
			push @{$runner->stack}, $runner->_fromint($num);
		}
	};
}

# runners for these are the same, since the script is complied
$opcodes{OP_PUSHDATA4}{runner} =
	$opcodes{OP_PUSHDATA1}{runner};

# runners for these are the same, since the script is complied
$opcodes{OP_PUSHDATA2}{runner} =
	$opcodes{OP_PUSHDATA1}{runner};

$opcodes{OP_NOTIF}{runner} = sub {
	$opcodes{OP_NOT}{runner}->(@_);
	$opcodes{OP_IF}{runner}->(@_);
};

$opcodes{OP_EQUALVERIFY}{runner} = sub {
	$opcodes{OP_EQUAL}{runner}->(@_);
	$opcodes{OP_VERIFY}{runner}->(@_);
};

$opcodes{OP_NUMEQUALVERIFY}{runner} = sub {
	$opcodes{OP_NUMEQUAL}{runner}->(@_);
	$opcodes{OP_VERIFY}{runner}->(@_);
};

$opcodes{OP_CHECKSIGVERIFY}{runner} = sub {
	$opcodes{OP_CHECKSIG}{runner}->(@_);
	$opcodes{OP_VERIFY}{runner}->(@_);
};

$opcodes{OP_CHECKMULTISIGVERIFY}{runner} = sub {
	$opcodes{OP_CHECKMULTISIG}{runner}->(@_);
	$opcodes{OP_VERIFY}{runner}->(@_);
};

my %opcodes_reverse = map { $opcodes{$_}{code}, $_ } keys %opcodes;

# aliases are added after setting up reverse mapping to end up with
# deterministic results of get_opcode_by_code. This means opcodes below will
# never be returned by that method.
$opcodes{OP_FALSE} = $opcodes{OP_0};
$opcodes{OP_TRUE} = $opcodes{OP_1};

%opcodes = map { $_, __PACKAGE__->new(name => $_, %{$opcodes{$_}}) } keys %opcodes;

sub get_opcode_by_code
{
	my ($self, $code) = @_;

	Bitcoin::Crypto::Exception::ScriptOpcode->raise(
		'undefined opcode code argument'
	) unless defined $code;

	Bitcoin::Crypto::Exception::ScriptOpcode->raise(
		"unknown opcode code " . unpack 'H*', $code
	) unless exists $opcodes_reverse{$code};

	return $opcodes{$opcodes_reverse{$code}};
}

sub get_opcode_by_name
{
	my ($self, $opcode) = @_;

	Bitcoin::Crypto::Exception::ScriptOpcode->raise(
		'undefined opcode name argument'
	) unless defined $opcode;

	Bitcoin::Crypto::Exception::ScriptOpcode->raise(
		"unknown opcode $opcode"
	) unless exists $opcodes{$opcode};

	return $opcodes{$opcode};
}

1;

