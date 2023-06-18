package Bitcoin::Crypto::Script::Opcode;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Digest::SHA1 qw(sha1);

use Bitcoin::Crypto qw(btc_pub);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Str StrLength CodeRef Bool);
use Bitcoin::Crypto::Util qw(hash160 hash256);

# some private helpers for opcodes

sub stack_error
{
	die 'stack error';
}

sub invalid_script
{
	Bitcoin::Crypto::Exception::ScriptInvalid->raise(
		'transaction was marked as invalid'
	);
}

use namespace::clean;

has param 'name' => (
	isa => Str,
);

has param 'code' => (
	isa => StrLength [1, 1],
);

has param 'needs_transaction' => (
	isa => Bool,
	default => 0,
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

			push @{$runner->stack}, $runner->from_int(-1);
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

			stack_error unless @$stack >= 1;
			if ($runner->to_bool(pop @$stack)) {

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

			invalid_script unless $runner->to_bool($stack->[-1]);

			# pop later so that problematic value can be seen on the stack
			pop @$stack;
		},
	},
	OP_RETURN => {
		code => "\x6a",
		runner => sub {
			my $runner = shift;

			invalid_script;
		},
	},
	OP_TOALTSTACK => {
		code => "\x6b",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @{$runner->alt_stack}, pop @$stack;
		},
	},
	OP_FROMALTSTACK => {
		code => "\x6c",
		runner => sub {
			my $runner = shift;
			my $alt = $runner->alt_stack;

			stack_error unless @$alt >= 1;
			push @{$runner->stack}, pop @$alt;
		},
	},
	OP_2DROP => {
		code => "\x6d",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			splice @$stack, -2, 2;
		},
	},
	OP_2DUP => {
		code => "\x6e",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, @$stack[-2, -1];
		},
	},
	OP_3DUP => {
		code => "\x6f",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 3;
			push @$stack, @$stack[-3, -2, -1];
		},
	},
	OP_2OVER => {
		code => "\x70",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 4;
			push @$stack, @$stack[-4, -3];
		},
	},
	OP_2ROT => {
		code => "\x71",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 6;
			push @$stack, splice @$stack, -6, 2;
		},
	},
	OP_2SWAP => {
		code => "\x72",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 4;
			push @$stack, splice @$stack, -4, 2;
		},
	},
	OP_IFDUP => {
		code => "\x73",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			if ($runner->to_bool($stack->[-1])) {
				push @$stack, $stack->[-1];
			}
		},
	},
	OP_DEPTH => {
		code => "\x74",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			push @$stack, $runner->from_int(scalar @$stack);
		},
	},
	OP_DROP => {
		code => "\x75",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			pop @$stack;
		},
	},
	OP_DUP => {
		code => "\x76",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $stack->[-1];
		},
	},
	OP_NIP => {
		code => "\x77",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			splice @$stack, -2, 1;
		},
	},
	OP_OVER => {
		code => "\x78",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $stack->[-2];
		},
	},
	OP_PICK => {
		code => "\x79",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;

			my $n = $runner->to_int(pop @$stack);
			stack_error if $n < 0 || $n >= @$stack;

			push @$stack, $stack->[-1 * ($n + 1)];
		},
	},
	OP_ROLL => {
		code => "\x7a",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;

			my $n = $runner->to_int(pop @$stack);
			stack_error if $n < 0 || $n >= @$stack;

			push @$stack, splice @$stack, -1 * ($n + 1), 1;
		},
	},
	OP_ROT => {
		code => "\x7b",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 3;
			push @$stack, splice @$stack, -3, 1;
		},
	},
	OP_SWAP => {
		code => "\x7c",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, splice @$stack, -2, 1;
		},
	},
	OP_TUCK => {
		code => "\x7d",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			splice @$stack, -2, 0, $stack->[-1];
		},
	},
	OP_SIZE => {
		code => "\x82",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int(length $stack->[-1]);
		},
	},
	OP_EQUAL => {
		code => "\x87",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(pop(@$stack) eq pop(@$stack));
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

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int($runner->to_int(pop @$stack) + 1);
		},
	},
	OP_1SUB => {
		code => "\x8c",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int($runner->to_int(pop @$stack) - 1);
		},
	},
	OP_NEGATE => {
		code => "\x8f",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int($runner->to_int(pop @$stack) * -1);
		},
	},
	OP_ABS => {
		code => "\x90",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int(abs $runner->to_int(pop @$stack));
		},
	},
	OP_NOT => {
		code => "\x91",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_bool($runner->to_int(pop @$stack) == 0);
		},
	},
	OP_0NOTEQUAL => {
		code => "\x92",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_bool($runner->to_int(pop @$stack) != 0);
		},
	},
	OP_ADD => {
		code => "\x93",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_int(
				$runner->to_int(pop @$stack)
					+ $runner->to_int(pop @$stack)
			);
		},
	},
	OP_SUB => {
		code => "\x94",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_int(
				-1 * $runner->to_int(pop @$stack)
					+ $runner->to_int(pop @$stack)
			);
		},
	},
	OP_BOOLAND => {
		code => "\x9a",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;

			my $second = $runner->to_int(pop @$stack) != 0;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack) != 0
					&& $second
			);
		},
	},
	OP_BOOLOR => {
		code => "\x9b",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;

			my $second = $runner->to_int(pop @$stack) != 0;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack) != 0
					|| $second
			);
		},
	},
	OP_NUMEQUAL => {
		code => "\x9c",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack)
					== $runner->to_int(pop @$stack)
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

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack)
					!= $runner->to_int(pop @$stack)
			);
		},
	},
	OP_LESSTHAN => {
		code => "\x9f",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack)
					> $runner->to_int(pop @$stack)
			);
		},
	},
	OP_GREATERTHAN => {
		code => "\xa0",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack)
					< $runner->to_int(pop @$stack)
			);
		},
	},
	OP_LESSTHANOREQUAL => {
		code => "\xa1",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack)
					>= $runner->to_int(pop @$stack)
			);
		},
	},
	OP_GREATERTHANOREQUAL => {
		code => "\xa2",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(
				$runner->to_int(pop @$stack)
					<= $runner->to_int(pop @$stack)
			);
		},
	},
	OP_MIN => {
		code => "\xa3",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			my ($first, $second) = splice @$stack, -2, 2;
			push @$stack, $runner->to_int($first) < $runner->to_int($second)
				? $first : $second;
		},
	},
	OP_MAX => {
		code => "\xa4",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			my ($first, $second) = splice @$stack, -2, 2;
			push @$stack, $runner->to_int($first) > $runner->to_int($second)
				? $first : $second;
		},
	},
	OP_WITHIN => {
		code => "\xa5",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 3;
			my ($first, $second, $third) = map { $runner->to_int($_) } splice @$stack, -3, 3;
			push @$stack, $runner->from_bool($first >= $second && $first < $third);
		},
	},
	OP_RIPEMD160 => {
		code => "\xa6",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, ripemd160(pop @$stack);
		},
	},
	OP_SHA1 => {
		code => "\xa7",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, sha1(pop @$stack);
		},
	},
	OP_SHA256 => {
		code => "\xa8",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, sha256(pop @$stack);
		},
	},
	OP_HASH160 => {
		code => "\xa9",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, hash160(pop @$stack);
		},
	},
	OP_HASH256 => {
		code => "\xaa",
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, hash256(pop @$stack);
		},
	},
	OP_CODESEPARATOR => {
		code => "\xab",
		needs_transaction => 1,

		runner => sub {
			my $runner = shift;
			$runner->_register_codeseparator;
		},
	},
	OP_CHECKSIG => {
		code => "\xac",
		needs_transaction => 1,

		runner => sub {
			my $runner = shift;

			my $stack = $runner->stack;
			stack_error unless @$stack >= 2;

			my $sig = shift @$stack;
			my $raw_pubkey = shift @$stack;
			my $hashtype = substr $sig, -1, 1, '';

			my $digest = $runner->transaction->get_digest($runner->subscript, unpack 'C', $hashtype);
			my $pubkey = btc_pub->from_str($raw_pubkey);

			my $result = $pubkey->verify_message($digest, $sig, 'hash256');
			push @$stack, $runner->from_bool($result);
		},
	},
	OP_CHECKSIGVERIFY => {
		code => "\xad",

		# see runner below
	},
	OP_CHECKMULTISIG => {
		code => "\xae",

		# runner => sub {
		# 	my $runner = shift;
		# },
	},
	OP_CHECKMULTISIGVERIFY => {
		code => "\xaf",

		# see runner below
	},
	OP_CHECKLOCKTIMEVERFIY => {
		code => "\xb1",
		needs_transaction => 1,

		runner => sub {
			my $runner = shift;

			my $stack = $runner->stack;
			stack_error unless @$stack >= 1;

			invalid_script
				if $runner->to_int($stack->[-1]) > $runner->transaction->locktime;

			pop @$stack;
		},
	},
	OP_CHECKSEQUENCEVERIFY => {
		code => "\xb2",

		# runner => sub {
		# 	my $runner = shift;
		# },
	},
);

for my $num (1 .. 16) {
	$opcodes{"OP_$num"} = {
		code => chr(0x50 + $num),
		runner => sub {
			my $runner = shift;
			push @{$runner->stack}, $runner->from_int($num);
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

# $opcodes{OP_CHECKMULTISIGVERIFY}{runner} = sub {
# 	$opcodes{OP_CHECKMULTISIG}{runner}->(@_);
# 	$opcodes{OP_VERIFY}{runner}->(@_);
# };

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

__END__

=head1 NAME

Bitcoin::Crypto::Script::Opcode - Bitcoin Script opcode

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script::Opcode;

	my $opcode1 = Bitcoin::Crypto::Script::Opcode->get_opcode_by_code("\x00");
	my $opcode2 = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name('OP_1');

	print $opcode1->name; # 'OP_0'
	print $opcode1->code; # "\x00"
	print 'implemented' if $opcode1->implemented;

=head1 DESCRIPTION

This is both a library of opcodes and a small struct-like class for opcodes.

=head1 INTERFACE

=head2 Class (static) methods

These methods are used to find an opcode.

=head3 get_opcode_by_name

	my $object = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($name);

Finds an opcode by its name (C<OP_XXX>) and returns an object instance.

If opcode was not found an exception is raised (C<Bitcoin::Crypto::Exception::ScriptOpcode>).

=head3 get_opcode_by_code

	my $object = Bitcoin::Crypto::Script::Opcode->get_opcode_by_code($bytestr);

Finds an opcode by its code (bytestring of length 1) and returns an object instance.

If opcode was not found an exception is raised (C<Bitcoin::Crypto::Exception::ScriptOpcode>).

=head2 Attributes

=head3 name

The name of the opcode (C<OP_XXX>).

=head3 code

The code of the opcode - a bytestring of length 1.

=head3 runner

A coderef which can be used to execute this opcode.

This is reserved for internal use only. If you want to know whether an opcode
is implemented, call L</implemented>

=head2 Methods

=head3 execute

Executes this opcode. Internal use only.

=head3 implemented

	my $bool = $object->implemented;

Returns true if this opcode is implemented within C<Bitcoin::Crypto>.

If an opcode is not implemented, a script containing it will refuse to run.
Serialization and deseralization will still work though.

=head1 CAVEATS

=head1 SEE ALSO

L<Bitcoin::Crypto::Script>

