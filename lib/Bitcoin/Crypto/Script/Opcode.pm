package Bitcoin::Crypto::Script::Opcode;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use List::Util qw(notall);

use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Digest::SHA1 qw(sha1);

use Bitcoin::Crypto qw(btc_pub);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Helpers qw(ecc);
use Bitcoin::Crypto::Util qw(hash160 hash256 get_public_key_compressed lift_x);
use Bitcoin::Crypto::Transaction::Input;

use namespace::clean;

has param 'name' => (
	isa => Str,
);

has param 'code' => (
	isa => IntMaxBits [8],
);

has param 'needs_transaction' => (
	isa => Bool,
	default => 0,
);

has param 'pushes' => (
	isa => Bool,
	default => 0,
);

# args for coderef are:
# - Bitcoin::Crypto::Script::Runner instance
# - Bitcoin::Crypto::Script::Opcode instance
has option 'on_compilation' => (
	isa => CodeRef,
);

# args for coderef are:
# - Bitcoin::Crypto::Script::Runner instance
# (additional args are possible depending on opcode type)
has option 'runner' => (
	isa => CodeRef,
	predicate => 'implemented',
);

sub _OP_NUM
{
	my ($class, $num) = @_;

	return sub {
		my $runner = shift;

		push @{$runner->stack}, $num == 0 ? '' : $runner->from_int($num);
	};
}

sub _OP_PUSHDATA
{
	return sub {
		my ($runner, $bytes) = @_;

		push @{$runner->stack}, $bytes;
	};
}

sub _OP_1NEGATE
{
	return sub {
		my $runner = shift;

		push @{$runner->stack}, $runner->from_int(-1);
	};
}

sub _OP_RESERVED
{
	return sub {
		my $runner = shift;
		$runner->_invalid_script;
	};
}

# does nothing
sub _OP_NOP
{
	return sub { };
}

sub _OP_VER
{
	return sub {
		my $runner = shift;
		$runner->_invalid_script;
	};
}

sub _OP_IF
{
	my ($class, $inverted) = @_;

	return sub {
		my ($runner, $else_pos, $endif_pos) = @_;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		my $value = pop @$stack;
		$value = $runner->is_tapscript ? $runner->to_minimal_bool($value) : $runner->to_bool($value);
		$runner->_invalid_script unless defined $value;
		$value = !$value if $inverted;

		if ($value) {

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
	}
}

# should only get called when IF branch ops are depleted
sub _OP_ELSE
{
	return sub {
		my ($runner, $endif_pos) = @_;

		$runner->_set_pos($endif_pos);
	};
}

# should only get called when IF or ELSE branch ops are depleted
# nothing to do here, will step to the next op
sub _OP_ENDIF
{
	my $class = shift;
	return $class->_OP_NOP;
}

sub _OP_VERIFY
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_invalid_script unless $runner->to_bool($stack->[-1]);

		# pop later so that problematic value can be seen on the stack
		pop @$stack;
	};
}

sub _OP_RETURN
{
	return sub {
		my $runner = shift;
		$runner->_invalid_script;
	};
}

sub _OP_TOALTSTACK
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @{$runner->alt_stack}, pop @$stack;
	};
}

sub _OP_FROMALTSTACK
{
	return sub {
		my $runner = shift;
		my $alt = $runner->alt_stack;

		$runner->_stack_error unless @$alt >= 1;
		push @{$runner->stack}, pop @$alt;
	};
}

sub _OP_2DROP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		splice @$stack, -2, 2;
	};
}

sub _OP_2DUP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, @$stack[-2, -1];
	};
}

sub _OP_3DUP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 3;
		push @$stack, @$stack[-3, -2, -1];
	};
}

sub _OP_2OVER
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 4;
		push @$stack, @$stack[-4, -3];
	};
}

sub _OP_2ROT
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 6;
		push @$stack, splice @$stack, -6, 2;
	};
}

sub _OP_2SWAP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 4;
		push @$stack, splice @$stack, -4, 2;
	};
}

sub _OP_IFDUP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		if ($runner->to_bool($stack->[-1])) {
			push @$stack, $stack->[-1];
		}
	};
}

sub _OP_DEPTH
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		push @$stack, $runner->from_int(scalar @$stack);
	};
}

sub _OP_DROP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		pop @$stack;
	};
}

sub _OP_DUP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $stack->[-1];
	};
}

sub _OP_NIP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		splice @$stack, -2, 1;
	};
}

sub _OP_OVER
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $stack->[-2];
	};
}

sub _OP_PICK
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;

		my $n = $runner->to_int(pop @$stack);
		$runner->_stack_error if $n < 0 || $n >= @$stack;

		push @$stack, $stack->[-1 * ($n + 1)];
	};
}

sub _OP_ROLL
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;

		my $n = $runner->to_int(pop @$stack);
		$runner->_stack_error if $n < 0 || $n >= @$stack;

		push @$stack, splice @$stack, -1 * ($n + 1), 1;
	};
}

sub _OP_ROT
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 3;
		push @$stack, splice @$stack, -3, 1;
	};
}

sub _OP_SWAP
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, splice @$stack, -2, 1;
	};
}

sub _OP_TUCK
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		splice @$stack, -2, 0, $stack->[-1];
	};
}

sub _OP_SIZE
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int(length $stack->[-1]);
	};
}

sub _OP_EQUAL
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_bool(pop(@$stack) eq pop(@$stack));
	};
}

sub _OP_EQUALVERIFY
{
	my ($class) = @_;

	my $op_equal = $class->_OP_EQUAL;
	my $op_verify = $class->_OP_VERIFY;

	return sub {
		$op_equal->(@_);
		$op_verify->(@_);
	};
}

sub _OP_1ADD
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int($runner->to_int(pop @$stack) + 1);
	};
}

sub _OP_1SUB
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int($runner->to_int(pop @$stack) - 1);
	};
}

sub _OP_NEGATE
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int($runner->to_int(pop @$stack) * -1);
	};
}

sub _OP_ABS
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int(abs $runner->to_int(pop @$stack));
	};
}

sub _OP_NOT
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_bool($runner->to_int(pop @$stack) == 0);
	};
}

sub _OP_0NOTEQUAL
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_bool($runner->to_int(pop @$stack) != 0);
	};
}

sub _OP_ADD
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_int(
			$runner->to_int(pop @$stack)
				+ $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_SUB
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_int(
			-1 * $runner->to_int(pop @$stack)
				+ $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_BOOLAND
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;

		my $second = $runner->to_int(pop @$stack) != 0;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack) != 0
				&& $second
		);
	};
}

sub _OP_BOOLOR
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;

		my $second = $runner->to_int(pop @$stack) != 0;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack) != 0
				|| $second
		);
	};
}

sub _OP_NUMEQUAL
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack)
				== $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_NUMEQUALVERIFY
{
	my ($class) = @_;

	my $op_numequal = $class->_OP_NUMEQUAL;
	my $op_verify = $class->_OP_VERIFY;

	return sub {
		$op_numequal->(@_);
		$op_verify->(@_);
	};
}

sub _OP_NUMNOTEQUAL
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack)
				!= $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_LESSTHAN
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack)
				> $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_GREATERTHAN
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack)
				< $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_LESSTHANOREQUAL
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack)
				>= $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_GREATERTHANOREQUAL
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $runner->from_bool(
			$runner->to_int(pop @$stack)
				<= $runner->to_int(pop @$stack)
		);
	};
}

sub _OP_MIN
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		my ($first, $second) = splice @$stack, -2, 2;
		push @$stack, $runner->to_int($first) < $runner->to_int($second)
			? $first : $second;
	};
}

sub _OP_MAX
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		my ($first, $second) = splice @$stack, -2, 2;
		push @$stack, $runner->to_int($first) > $runner->to_int($second)
			? $first : $second;
	};
}

sub _OP_WITHIN
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 3;
		my ($first, $second, $third) = map { $runner->to_int($_) } splice @$stack, -3, 3;
		push @$stack, $runner->from_bool($first >= $second && $first < $third);
	};
}

sub _OP_RIPEMD160
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, ripemd160(pop @$stack);
	};
}

sub _OP_SHA1
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, sha1(pop @$stack);
	};
}

sub _OP_SHA256
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, sha256(pop @$stack);
	};
}

sub _OP_HASH160
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, hash160(pop @$stack);
	};
}

sub _OP_HASH256
{
	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, hash256(pop @$stack);
	};
}

sub _OP_CODESEPARATOR
{
	return sub {
		my $runner = shift;
		$runner->_register_codeseparator;
	};
}

sub _OP_CHECKSIG
{
	return sub {
		my $runner = shift;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 2;

		my $raw_pubkey = pop @$stack;
		my $sig = pop @$stack;

		my $hashtype = unpack 'C', substr $sig, -1, 1, '';
		my $pubkey = btc_pub->from_serialized($raw_pubkey);

		$runner->_script_error('SegWit validation requires compressed public key')
			if !$pubkey->compressed && $runner->transaction->is_native_segwit;

		my $preimage = $runner->transaction->get_digest($runner->subscript, $hashtype);
		my $result = $pubkey->verify_message($preimage, $sig);

		push @$stack, $runner->from_bool($result);
	};
}

sub _OP_CHECKSIGVERIFY
{
	my ($class) = @_;

	my $op_checksig = $class->_OP_CHECKSIG;
	my $op_verify = $class->_OP_VERIFY;

	return sub {
		$op_checksig->(@_);
		$op_verify->(@_);
	};
}

sub _OP_CHECKMULTISIG
{
	return sub {
		my $runner = shift;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 1;

		my $pubkeys_num = $runner->to_int(pop @$stack);
		$runner->_stack_error unless $pubkeys_num > 0 && @$stack >= $pubkeys_num;
		my @pubkeys = splice @$stack, -$pubkeys_num;

		$runner->_script_error('SegWit validation requires all public keys to be compressed')
			if $runner->transaction->is_native_segwit && notall { get_public_key_compressed($_) } @pubkeys;

		my $signatures_num = $runner->to_int(pop @$stack);
		$runner->_stack_error unless $signatures_num > 0 && @$stack >= $signatures_num;
		my @signatures = splice @$stack, -$signatures_num;

		my $subscript = $runner->subscript;
		my $found;
		while (my $sig = shift @signatures) {
			my $hashtype = substr $sig, -1, 1, '';

			my $digest = $runner->transaction->get_digest($subscript, unpack 'C', $hashtype);
			$found = !!0;
			while (my $raw_pubkey = shift @pubkeys) {
				my $pubkey = btc_pub->from_serialized($raw_pubkey);
				$found = $pubkey->verify_message($digest, $sig);
				last if $found;
			}

			last if !$found;
		}

		# Remove extra unused value from the stack
		my $unused = pop @$stack;
		$runner->_script_error('OP_CHECKMULTISIG dummy argument must be empty')
			if length $unused;

		my $result = $found && !@signatures;
		push @$stack, $runner->from_bool($result);
	};
}

sub _OP_CHECKMULTISIGVERIFY
{
	my ($class) = @_;

	my $checkmultisig = $class->_OP_CHECKMULTISIG;
	my $verify = $class->_OP_VERIFY;

	return sub {
		$checkmultisig->(@_);
		$verify->(@_);
	};
}

sub _OP_CHECKLOCKTIMEVERIFY
{
	return sub {
		my $runner = shift;
		my $transaction = $runner->transaction;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 1;

		my $c1 = $runner->to_int($stack->[-1], 5);
		my $c2 = $runner->transaction->locktime;

		$runner->_invalid_script
			if $c1 < 0;

		my $c1_is_height = $c1 < Bitcoin::Crypto::Constants::locktime_height_threshold;
		my $c2_is_height = $c2 < Bitcoin::Crypto::Constants::locktime_height_threshold;

		$runner->_invalid_script
			unless !!$c1_is_height == !!$c2_is_height;

		$runner->_invalid_script
			if $c1 > $c2;

		$runner->_invalid_script
			if $transaction->this_input->sequence_no == Bitcoin::Crypto::Constants::max_sequence_no;

		pop @$stack;
	};
}

sub _OP_CHECKSEQUENCEVERIFY
{
	return sub {
		my $runner = shift;
		my $transaction = $runner->transaction;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 1;

		my $c1 = $runner->to_int($stack->[-1], 5);

		$runner->_invalid_script
			if $c1 < 0;

		if (!($c1 & (1 << 31))) {
			$runner->_invalid_script
				if $transaction->version < 2;

			my $c2 = $transaction->this_input->sequence_no;

			$runner->_invalid_script
				if $c2 & (1 << 31);

			my $c1_is_time = $c1 & (1 << 22);
			my $c2_is_time = $c2 & (1 << 22);

			$runner->_invalid_script
				if !!$c1_is_time ne !!$c2_is_time;

			$runner->_invalid_script
				if ($c1 & 0x0000ffff) > ($c2 & 0x0000ffff);
		}

		pop @$stack;
	};
}

sub _build_opcodes
{
	my ($class) = @_;

	my %opcodes = (
		OP_0 => {
			code => 0x00,
			pushes => !!1,
			runner => $class->_OP_NUM(0),
		},
		OP_PUSHDATA1 => {
			code => 0x4c,
			pushes => !!1,
			runner => $class->_OP_PUSHDATA,
		},
		OP_PUSHDATA2 => {
			code => 0x4d,
			pushes => !!1,
			runner => $class->_OP_PUSHDATA,
		},
		OP_PUSHDATA4 => {
			code => 0x4e,
			pushes => !!1,
			runner => $class->_OP_PUSHDATA,
		},
		OP_1NEGATE => {
			code => 0x4f,
			runner => $class->_OP_1NEGATE,
		},
		OP_RESERVED => {
			code => 0x50,
			runner => $class->_OP_RESERVED,
		},
		OP_NOP => {
			code => 0x61,
			runner => $class->_OP_NOP,
		},
		OP_VER => {
			code => 0x62,
			runner => $class->_OP_VER,
		},
		OP_IF => {
			code => 0x63,
			runner => $class->_OP_IF,
		},
		OP_NOTIF => {
			code => 0x64,
			runner => $class->_OP_IF(!!1),
		},
		OP_VERIF => {
			code => 0x65,
			on_compilation => sub {
				my ($runner, $opcode) = @_;
				$runner->_invalid_script;
			},
		},
		OP_VERNOTIF => {
			code => 0x66,
			on_compilation => sub {
				my ($runner, $opcode) = @_;
				$runner->_invalid_script;
			},
		},
		OP_ELSE => {
			code => 0x67,
			runner => $class->_OP_ELSE,
		},
		OP_ENDIF => {
			code => 0x68,
			runner => $class->_OP_ENDIF,
		},
		OP_VERIFY => {
			code => 0x69,
			runner => $class->_OP_VERIFY,
		},
		OP_RETURN => {
			code => 0x6a,
			runner => $class->_OP_RETURN,
		},
		OP_TOALTSTACK => {
			code => 0x6b,
			runner => $class->_OP_TOALTSTACK,
		},
		OP_FROMALTSTACK => {
			code => 0x6c,
			runner => $class->_OP_FROMALTSTACK,
		},
		OP_2DROP => {
			code => 0x6d,
			runner => $class->_OP_2DROP,
		},
		OP_2DUP => {
			code => 0x6e,
			runner => $class->_OP_2DUP,
		},
		OP_3DUP => {
			code => 0x6f,
			runner => $class->_OP_3DUP,
		},
		OP_2OVER => {
			code => 0x70,
			runner => $class->_OP_2OVER,
		},
		OP_2ROT => {
			code => 0x71,
			runner => $class->_OP_2ROT,
		},
		OP_2SWAP => {
			code => 0x72,
			runner => $class->_OP_2SWAP,
		},
		OP_IFDUP => {
			code => 0x73,
			runner => $class->_OP_IFDUP,
		},
		OP_DEPTH => {
			code => 0x74,
			runner => $class->_OP_DEPTH,
		},
		OP_DROP => {
			code => 0x75,
			runner => $class->_OP_DROP,
		},
		OP_DUP => {
			code => 0x76,
			runner => $class->_OP_DUP,
		},
		OP_NIP => {
			code => 0x77,
			runner => $class->_OP_NIP,
		},
		OP_OVER => {
			code => 0x78,
			runner => $class->_OP_OVER,
		},
		OP_PICK => {
			code => 0x79,
			runner => $class->_OP_PICK,
		},
		OP_ROLL => {
			code => 0x7a,
			runner => $class->_OP_ROLL,
		},
		OP_ROT => {
			code => 0x7b,
			runner => $class->_OP_ROT,
		},
		OP_SWAP => {
			code => 0x7c,
			runner => $class->_OP_SWAP,
		},
		OP_TUCK => {
			code => 0x7d,
			runner => $class->_OP_TUCK,
		},
		OP_SIZE => {
			code => 0x82,
			runner => $class->_OP_SIZE,
		},
		OP_EQUAL => {
			code => 0x87,
			runner => $class->_OP_EQUAL,
		},
		OP_EQUALVERIFY => {
			code => 0x88,
			runner => $class->_OP_EQUALVERIFY
		},
		OP_RESERVED1 => {
			code => 0x89,
			runner => $class->_OP_RESERVED,
		},
		OP_RESERVED2 => {
			code => 0x8a,
			runner => $class->_OP_RESERVED,
		},
		OP_1ADD => {
			code => 0x8b,
			runner => $class->_OP_1ADD,
		},
		OP_1SUB => {
			code => 0x8c,
			runner => $class->_OP_1SUB,
		},
		OP_NEGATE => {
			code => 0x8f,
			runner => $class->_OP_NEGATE,
		},
		OP_ABS => {
			code => 0x90,
			runner => $class->_OP_ABS,
		},
		OP_NOT => {
			code => 0x91,
			runner => $class->_OP_NOT,
		},
		OP_0NOTEQUAL => {
			code => 0x92,
			runner => $class->_OP_0NOTEQUAL,
		},
		OP_ADD => {
			code => 0x93,
			runner => $class->_OP_ADD,
		},
		OP_SUB => {
			code => 0x94,
			runner => $class->_OP_SUB,
		},
		OP_BOOLAND => {
			code => 0x9a,
			runner => $class->_OP_BOOLAND,
		},
		OP_BOOLOR => {
			code => 0x9b,
			runner => $class->_OP_BOOLOR,
		},
		OP_NUMEQUAL => {
			code => 0x9c,
			runner => $class->_OP_NUMEQUAL,
		},
		OP_NUMEQUALVERIFY => {
			code => 0x9d,
			runner => $class->_OP_NUMEQUALVERIFY,
		},
		OP_NUMNOTEQUAL => {
			code => 0x9e,
			runner => $class->_OP_NUMNOTEQUAL,
		},
		OP_LESSTHAN => {
			code => 0x9f,
			runner => $class->_OP_LESSTHAN,
		},
		OP_GREATERTHAN => {
			code => 0xa0,
			runner => $class->_OP_GREATERTHAN,
		},
		OP_LESSTHANOREQUAL => {
			code => 0xa1,
			runner => $class->_OP_LESSTHANOREQUAL,
		},
		OP_GREATERTHANOREQUAL => {
			code => 0xa2,
			runner => $class->_OP_GREATERTHANOREQUAL,
		},
		OP_MIN => {
			code => 0xa3,
			runner => $class->_OP_MIN,
		},
		OP_MAX => {
			code => 0xa4,
			runner => $class->_OP_MAX,
		},
		OP_WITHIN => {
			code => 0xa5,
			runner => $class->_OP_WITHIN,
		},
		OP_RIPEMD160 => {
			code => 0xa6,
			runner => $class->_OP_RIPEMD160,
		},
		OP_SHA1 => {
			code => 0xa7,
			runner => $class->_OP_SHA1,
		},
		OP_SHA256 => {
			code => 0xa8,
			runner => $class->_OP_SHA256,
		},
		OP_HASH160 => {
			code => 0xa9,
			runner => $class->_OP_HASH160,
		},
		OP_HASH256 => {
			code => 0xaa,
			runner => $class->_OP_HASH256,
		},
		OP_CODESEPARATOR => {
			code => 0xab,
			needs_transaction => !!1,
			runner => $class->_OP_CODESEPARATOR,
		},
		OP_CHECKSIG => {
			code => 0xac,
			needs_transaction => !!1,
			runner => $class->_OP_CHECKSIG,
		},
		OP_CHECKSIGVERIFY => {
			code => 0xad,
			needs_transaction => !!1,
			runner => $class->_OP_CHECKSIGVERIFY
		},
		OP_CHECKMULTISIG => {
			code => 0xae,
			needs_transaction => !!1,
			runner => $class->_OP_CHECKMULTISIG,
		},
		OP_CHECKMULTISIGVERIFY => {
			code => 0xaf,
			needs_transaction => !!1,
			runner => $class->_OP_CHECKMULTISIGVERIFY
		},
		OP_CHECKLOCKTIMEVERIFY => {
			code => 0xb1,
			needs_transaction => !!1,
			runner => $class->_OP_CHECKLOCKTIMEVERIFY,
		},
		OP_CHECKSEQUENCEVERIFY => {
			code => 0xb2,
			needs_transaction => !!1,
			runner => $class->_OP_CHECKSEQUENCEVERIFY,
		},
	);

	for my $num (1 .. 75) {
		$opcodes{"OP_PUSH$num"} = {
			name => 'OP_PUSH',
			code => $num,
			pushes => !!1,
			runner => $class->_OP_PUSHDATA,
		};
	}

	for my $num (1 .. 16) {
		$opcodes{"OP_$num"} = {
			code => 0x50 + $num,
			pushes => !!1,
			runner => $class->_OP_NUM($num),
		};
	}

	for my $num (1, 4 .. 10) {
		$opcodes{"OP_NOP$num"} = {
			code => 0xaf + $num,
			runner => $class->_OP_NOP,
		};
	}

	# aliases - prefixed with underscore
	$opcodes{_OP_FALSE} = $opcodes{OP_0};
	$opcodes{_OP_TRUE} = $opcodes{OP_1};

	return %opcodes;
}

sub opcodes
{
	my ($self) = @_;
	my $class = ref $self || $self;

	state $maps = {};
	return $maps->{$class} //= do {
		my %opcodes = $class->_build_opcodes;
		+{
			map {
				my $name = $_;
				$name =~ s/^_//;
				$_, $self->new(name => $name, %{$opcodes{$_}})
			} keys %opcodes
		};
	};
}

sub opcodes_reverse
{
	my ($self) = @_;
	my $class = ref $self || $self;

	state $maps = {};
	return $maps->{$class} //= do {
		my %codes = %{$self->opcodes};
		+{map { $codes{$_}{code}, $codes{$_} } grep { $_ !~ /^_/ } keys %codes};
	};
}

sub execute
{
	my ($self, @args) = @_;

	die $self->name . ' is not implemented'
		unless $self->implemented;

	return $self->runner->(@args);
}

sub _make_unknown
{
	my ($self, $code) = @_;

	return $self->new(
		name => 'UNKNOWN',
		code => $code,
		runner => $self->_OP_RESERVED,
	);
}

signature_for get_opcode_by_code => (
	method => Str,
	positional => [IntMaxBits [8]],
);

sub get_opcode_by_code
{
	my ($self, $code) = @_;
	my $hash = $self->opcodes_reverse;

	return $hash->{$code} // $self->_make_unknown($code);
}

signature_for get_opcode_by_name => (
	method => Str,
	positional => [Str],
);

sub get_opcode_by_name
{
	my ($self, $name) = @_;
	my $hash = $self->opcodes;

	my $opcode = $hash->{$name} || $hash->{"_$name"};

	Bitcoin::Crypto::Exception::ScriptOpcode->raise(
		sprintf "unknown opcode %s (%s)", $name, ref $self || $self
	) unless $opcode;

	return $opcode;
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Script::Opcode - Bitcoin Script opcode

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script::Opcode;

	my $opcode1 = Bitcoin::Crypto::Script::Opcode->get_opcode_by_code(0x00);
	my $opcode2 = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name('OP_1');

	print $opcode1->name; # 'OP_0'
	print $opcode1->code; # 0
	print 'implemented' if $opcode1->implemented;

=head1 DESCRIPTION

This is both a library of opcodes and a small struct-like class for opcodes.

=head1 INTERFACE

=head2 Class (static) methods

These methods are used to find an opcode.

=head3 get_opcode_by_name

	my $object = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($name);

Finds an opcode by its name (C<OP_XXX>) and returns an object instance.

If opcode was not found an exception is raised
(C<Bitcoin::Crypto::Exception::ScriptOpcode>).

=head3 get_opcode_by_code

	my $object = Bitcoin::Crypto::Script::Opcode->get_opcode_by_code($int);

Finds an opcode by its code (integer in range 0-255) and returns an object
instance.

If opcode was not found, an C<UNKNOWN> opcode is returned which marks the
script as invalid on execution.

=head2 Attributes

=head3 name

The name of the opcode (C<OP_XXX>).

=head3 code

The code of the opcode - a bytestring of length 1.

=head3 runner

A coderef which can be used to execute this opcode.

=head2 Methods

=head3 execute

Executes this opcode. Internal use only.

=head1 SEE ALSO

L<Bitcoin::Crypto::Script>

