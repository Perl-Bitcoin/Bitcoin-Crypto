package Bitcoin::Crypto::Script::Opcode;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use List::Util qw(notall);

use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Digest::SHA1 qw(sha1);

use Bitcoin::Crypto qw(btc_pub);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Str IntMaxBits CodeRef Bool);
use Bitcoin::Crypto::Util qw(hash160 hash256 get_public_key_compressed);
use Bitcoin::Crypto::Transaction::Input;

# some private helpers for opcodes

sub stack_error
{
	die 'stack error';
}

sub invalid_script
{
	Bitcoin::Crypto::Exception::TransactionScript->raise(
		'transaction was marked as invalid'
	);
}

sub script_error
{
	Bitcoin::Crypto::Exception::TransactionScript->raise(
		shift
	);
}

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
		code => 0x00,
		pushes => !!1,
		runner => sub {
			my $runner = shift;

			push @{$runner->stack}, '';
		},
	},
	OP_PUSHDATA1 => {
		code => 0x4c,
		pushes => !!1,
		runner => sub {
			my ($runner, $bytes) = @_;

			push @{$runner->stack}, $bytes;
		},
	},
	OP_PUSHDATA2 => {
		code => 0x4d,
		pushes => !!1,

		# see runner below
	},
	OP_PUSHDATA4 => {
		code => 0x4e,
		pushes => !!1,

		# see runner below
	},
	OP_1NEGATE => {
		code => 0x4f,
		runner => sub {
			my $runner = shift;

			push @{$runner->stack}, $runner->from_int(-1);
		},
	},
	OP_RESERVED => {
		code => 0x50,
		runner => sub { invalid_script },
	},
	OP_NOP => {
		code => 0x61,
		runner => sub {

			# does nothing
		},
	},
	OP_VER => {
		code => 0x62,
		runner => sub { invalid_script },
	},
	OP_IF => {
		code => 0x63,
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
		code => 0x64,

		# see runner below
	},
	OP_VERIF => {
		code => 0x65,

		# NOTE: should also be invalid if the op is not run
		runner => sub { invalid_script },
	},
	OP_VERNOTIF => {
		code => 0x66,

		# NOTE: should also be invalid if the op is not run
		runner => sub { invalid_script },
	},
	OP_ELSE => {
		code => 0x67,

		# should only get called when IF branch ops are depleted
		runner => sub {
			my ($runner, $endif_pos) = @_;

			$runner->_set_pos($endif_pos);
		},
	},
	OP_ENDIF => {
		code => 0x68,

		# should only get called when IF or ELSE branch ops are depleted
		runner => sub {

			# nothing to do here, will step to the next op
		},
	},
	OP_VERIFY => {
		code => 0x69,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			invalid_script unless $runner->to_bool($stack->[-1]);

			# pop later so that problematic value can be seen on the stack
			pop @$stack;
		},
	},
	OP_RETURN => {
		code => 0x6a,
		runner => sub { invalid_script },
	},
	OP_TOALTSTACK => {
		code => 0x6b,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @{$runner->alt_stack}, pop @$stack;
		},
	},
	OP_FROMALTSTACK => {
		code => 0x6c,
		runner => sub {
			my $runner = shift;
			my $alt = $runner->alt_stack;

			stack_error unless @$alt >= 1;
			push @{$runner->stack}, pop @$alt;
		},
	},
	OP_2DROP => {
		code => 0x6d,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			splice @$stack, -2, 2;
		},
	},
	OP_2DUP => {
		code => 0x6e,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, @$stack[-2, -1];
		},
	},
	OP_3DUP => {
		code => 0x6f,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 3;
			push @$stack, @$stack[-3, -2, -1];
		},
	},
	OP_2OVER => {
		code => 0x70,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 4;
			push @$stack, @$stack[-4, -3];
		},
	},
	OP_2ROT => {
		code => 0x71,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 6;
			push @$stack, splice @$stack, -6, 2;
		},
	},
	OP_2SWAP => {
		code => 0x72,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 4;
			push @$stack, splice @$stack, -4, 2;
		},
	},
	OP_IFDUP => {
		code => 0x73,
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
		code => 0x74,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			push @$stack, $runner->from_int(scalar @$stack);
		},
	},
	OP_DROP => {
		code => 0x75,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			pop @$stack;
		},
	},
	OP_DUP => {
		code => 0x76,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $stack->[-1];
		},
	},
	OP_NIP => {
		code => 0x77,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			splice @$stack, -2, 1;
		},
	},
	OP_OVER => {
		code => 0x78,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $stack->[-2];
		},
	},
	OP_PICK => {
		code => 0x79,
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
		code => 0x7a,
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
		code => 0x7b,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 3;
			push @$stack, splice @$stack, -3, 1;
		},
	},
	OP_SWAP => {
		code => 0x7c,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, splice @$stack, -2, 1;
		},
	},
	OP_TUCK => {
		code => 0x7d,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			splice @$stack, -2, 0, $stack->[-1];
		},
	},
	OP_SIZE => {
		code => 0x82,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int(length $stack->[-1]);
		},
	},
	OP_EQUAL => {
		code => 0x87,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 2;
			push @$stack, $runner->from_bool(pop(@$stack) eq pop(@$stack));
		},
	},
	OP_EQUALVERIFY => {
		code => 0x88,

		# see runner below
	},
	OP_RESERVED1 => {
		code => 0x89,
		runner => sub { invalid_script },
	},
	OP_RESERVED2 => {
		code => 0x8a,
		runner => sub { invalid_script },
	},
	OP_1ADD => {
		code => 0x8b,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int($runner->to_int(pop @$stack) + 1);
		},
	},
	OP_1SUB => {
		code => 0x8c,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int($runner->to_int(pop @$stack) - 1);
		},
	},
	OP_NEGATE => {
		code => 0x8f,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int($runner->to_int(pop @$stack) * -1);
		},
	},
	OP_ABS => {
		code => 0x90,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_int(abs $runner->to_int(pop @$stack));
		},
	},
	OP_NOT => {
		code => 0x91,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_bool($runner->to_int(pop @$stack) == 0);
		},
	},
	OP_0NOTEQUAL => {
		code => 0x92,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, $runner->from_bool($runner->to_int(pop @$stack) != 0);
		},
	},
	OP_ADD => {
		code => 0x93,
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
		code => 0x94,
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
		code => 0x9a,
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
		code => 0x9b,
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
		code => 0x9c,
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
		code => 0x9d,

		# see runner below
	},
	OP_NUMNOTEQUAL => {
		code => 0x9e,
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
		code => 0x9f,
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
		code => 0xa0,
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
		code => 0xa1,
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
		code => 0xa2,
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
		code => 0xa3,
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
		code => 0xa4,
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
		code => 0xa5,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 3;
			my ($first, $second, $third) = map { $runner->to_int($_) } splice @$stack, -3, 3;
			push @$stack, $runner->from_bool($first >= $second && $first < $third);
		},
	},
	OP_RIPEMD160 => {
		code => 0xa6,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, ripemd160(pop @$stack);
		},
	},
	OP_SHA1 => {
		code => 0xa7,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, sha1(pop @$stack);
		},
	},
	OP_SHA256 => {
		code => 0xa8,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, sha256(pop @$stack);
		},
	},
	OP_HASH160 => {
		code => 0xa9,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, hash160(pop @$stack);
		},
	},
	OP_HASH256 => {
		code => 0xaa,
		runner => sub {
			my $runner = shift;
			my $stack = $runner->stack;

			stack_error unless @$stack >= 1;
			push @$stack, hash256(pop @$stack);
		},
	},
	OP_CODESEPARATOR => {
		code => 0xab,
		needs_transaction => !!1,

		runner => sub {
			my $runner = shift;
			$runner->_register_codeseparator;
		},
	},
	OP_CHECKSIG => {
		code => 0xac,
		needs_transaction => !!1,

		runner => sub {
			my $runner = shift;

			my $stack = $runner->stack;
			stack_error unless @$stack >= 2;

			my $raw_pubkey = pop @$stack;
			my $sig = pop @$stack;
			my $hashtype = substr $sig, -1, 1, '';

			my $digest = $runner->transaction->get_digest($runner->subscript, unpack 'C', $hashtype);
			my $pubkey = btc_pub->from_serialized($raw_pubkey);

			script_error('SegWit validation requires compressed public key')
				if !$pubkey->compressed && $runner->transaction->is_native_segwit;

			my $result = $pubkey->verify_message($digest, $sig);
			push @$stack, $runner->from_bool($result);
		},
	},
	OP_CHECKSIGVERIFY => {
		code => 0xad,
		needs_transaction => !!1,

		# see runner below
	},
	OP_CHECKMULTISIG => {
		code => 0xae,
		needs_transaction => !!1,

		runner => sub {
			my $runner = shift;

			my $stack = $runner->stack;
			stack_error unless @$stack >= 1;

			my $pubkeys_num = $runner->to_int(pop @$stack);
			stack_error unless $pubkeys_num > 0 && @$stack >= $pubkeys_num;
			my @pubkeys = splice @$stack, -$pubkeys_num;

			script_error('SegWit validation requires all public keys to be compressed')
				if $runner->transaction->is_native_segwit && notall { get_public_key_compressed($_) } @pubkeys;

			my $signatures_num = $runner->to_int(pop @$stack);
			stack_error unless $signatures_num > 0 && @$stack >= $signatures_num;
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
			script_error('OP_CHECKMULTISIG dummy argument must be empty')
				if length $unused;

			my $result = $found && !@signatures;
			push @$stack, $runner->from_bool($result);
		},
	},
	OP_CHECKMULTISIGVERIFY => {
		code => 0xaf,
		needs_transaction => !!1,

		# see runner below
	},
	OP_NOP1 => {
		code => 0xb0,
		runner => sub { 'NOP' },
	},
	OP_CHECKLOCKTIMEVERIFY => {
		code => 0xb1,
		needs_transaction => !!1,

		runner => sub {
			my $runner = shift;
			my $transaction = $runner->transaction;

			my $stack = $runner->stack;
			stack_error unless @$stack >= 1;

			my $c1 = $runner->to_int($stack->[-1]);
			my $c2 = $runner->transaction->locktime;

			invalid_script
				if $c1 < 0;

			my $c1_is_height = $c1 < Bitcoin::Crypto::Constants::locktime_height_threshold;
			my $c2_is_height = $c2 < Bitcoin::Crypto::Constants::locktime_height_threshold;

			invalid_script
				if !!$c1_is_height ne !!$c2_is_height;

			invalid_script
				if $c1 > $c2;

			my $input = $transaction->inputs->[$transaction->input_index];
			invalid_script
				if $input->sequence_no == Bitcoin::Crypto::Constants::max_sequence_no;

			pop @$stack;
		},
	},
	OP_CHECKSEQUENCEVERIFY => {
		code => 0xb2,
		needs_transaction => !!1,

		runner => sub {
			my $runner = shift;
			my $transaction = $runner->transaction;

			my $stack = $runner->stack;
			stack_error unless @$stack >= 1;

			my $c1 = $runner->to_int($stack->[-1]);

			invalid_script
				if $c1 < 0;

			if (!($c1 & (1 << 31))) {
				invalid_script
					if $transaction->version < 2;

				my $c2 = $transaction->this_input->sequence_no;

				invalid_script
					if $c2 & (1 << 31);

				my $c1_is_time = $c1 & (1 << 22);
				my $c2_is_time = $c2 & (1 << 22);

				invalid_script
					if !!$c1_is_time ne !!$c2_is_time;

				invalid_script
					if ($c1 & 0x0000ffff) > ($c2 & 0x0000ffff);
			}

			pop @$stack;
		},
	},
	OP_NOP4 => {
		code => 0xb3,
		runner => sub { 'NOP' },
	},
	OP_NOP5 => {
		code => 0xb4,
		runner => sub { 'NOP' },
	},
	OP_NOP6 => {
		code => 0xb5,
		runner => sub { 'NOP' },
	},
	OP_NOP7 => {
		code => 0xb6,
		runner => sub { 'NOP' },
	},
	OP_NOP8 => {
		code => 0xb7,
		runner => sub { 'NOP' },
	},
	OP_NOP9 => {
		code => 0xb8,
		runner => sub { 'NOP' },
	},
	OP_NOP10 => {
		code => 0xb9,
		runner => sub { 'NOP' },
	},
);

for my $num (1 .. 16) {
	$opcodes{"OP_$num"} = {
		code => 0x50 + $num,
		pushes => !!1,
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

signature_for get_opcode_by_code => (
	method => Str,
	positional => [IntMaxBits [8]],
);

sub get_opcode_by_code
{
	my ($self, $code) = @_;

	Bitcoin::Crypto::Exception::ScriptOpcode->raise(
		"unknown opcode code " . unpack 'H*', $code
	) unless exists $opcodes_reverse{$code};

	return $opcodes{$opcodes_reverse{$code}};
}

signature_for get_opcode_by_name => (
	method => Str,
	positional => [Str],
);

sub get_opcode_by_name
{
	my ($self, $name) = @_;

	Bitcoin::Crypto::Exception::ScriptOpcode->raise(
		"unknown opcode $name"
	) unless exists $opcodes{$name};

	return $opcodes{$name};
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

If opcode was not found an exception is raised (C<Bitcoin::Crypto::Exception::ScriptOpcode>).

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

