package Bitcoin::Crypto::Script::Opcode;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;

use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Digest::SHA1 qw(sha1);
use List::Util qw(notall none);
use Feature::Compat::Try;

use Bitcoin::Crypto qw(btc_pub);
use Bitcoin::Crypto::Constants qw(:script :sighash :transaction);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Util qw(hash160 hash256);
use Bitcoin::Crypto::Helpers qw(standard_push check_strict_public_key check_strict_der_signature die_no_trace);
use Bitcoin::Crypto::Transaction::Input;

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

has param 'pushop' => (
	isa => Bool,
	default => 0,
);

has param 'sigop' => (
	isa => Bool,
	default => 0,
);

# args for coderef are:
# - Bitcoin::Crypto::Script::Compiler instance
# - Compiled opcode (array from compile method in Runner)
# - Compilation context (hashref)
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

sub _verify_stack
{
	my $class = shift;
	my $runner = shift;

	if (@{$runner->stack} + @{$runner->alt_stack} > SCRIPT_MAX_STACK_ELEMENTS) {
		$runner->_invalid_script('maximum stack size exceeded');
	}
}

sub _compile_OP_NUM
{
	my ($class, $num) = @_;

	# avoid cyclical uses
	require Bitcoin::Crypto::Script::Runner;

	return sub {
		my ($compiler, $op, $context) = @_;

		push @$op, $num == 0 ? '' : Bitcoin::Crypto::Script::Runner->from_int($num);
	};
}

sub _compile_OP_PUSH
{
	my ($class, $size) = @_;

	return sub {
		my ($compiler, $op, $context) = @_;

		push @$op, $compiler->_compile_data_push($context, $size);
		$op->[1] .= $op->[2];
	};
}

sub _compile_OP_PUSHDATA
{
	my ($class, $length) = @_;

	state $formats = {
		1 => 'C',
		2 => 'v',
		4 => 'V',
	};

	my $format = $formats->{$length}
		// die 'bad pushdata length';

	return sub {
		my ($compiler, $op, $context) = @_;

		my $raw_size = substr $context->{serialized}, $context->{offset}, $length;
		my $size = unpack $format, $raw_size;
		$context->{offset} += $length;

		push @$op, $compiler->_compile_data_push($context, $size);
		$op->[1] .= $raw_size . $op->[2];
	};
}

sub _compile_OP_IF
{
	my ($class) = @_;

	return sub {
		my ($compiler, $op, $context) = @_;

		if ($context->{branch}{if}) {
			my $prev = {%{$context->{branch}}};
			$context->{branch} = {
				previous => $prev,
			};
		}

		$context->{branch}{if} = $op;
		$context->{branch}{execution_chain} = [$op];
	};
}

sub _compile_OP_ELSE
{
	my ($class) = @_;

	return sub {
		my ($compiler, $op, $context) = @_;

		$compiler->_invalid_script(
			'OP_ELSE found but no previous OP_IF or OP_NOTIF'
		) if !$context->{branch}{if};

		# set up jump point for previous else
		my $chain = $context->{branch}{execution_chain};
		push @{$chain->[-1]}, $context->{position};

		# save else for later
		push @{$chain}, $op;
	};
}

sub _compile_OP_ENDIF
{
	my ($class) = @_;

	return sub {
		my ($compiler, $op, $context) = @_;

		$compiler->_invalid_script(
			'OP_ENDIF found but no previous OP_IF or OP_NOTIF'
		) if !$context->{branch}{if};

		# set up jump point for last execution element (if or else)
		my $chain = $context->{branch}{execution_chain};
		push @{$chain->[-1]}, $context->{position};

		if ($context->{branch}{previous}) {
			$context->{branch} = $context->{branch}{previous};
		}
		else {
			delete $context->{branch};
		}
	};
}

sub _compile_OP_VERIF
{
	my ($class) = @_;

	return sub {
		my ($compiler, $op, $context) = @_;

		$compiler->_invalid_script('OP_VERIF encountered');
	};
}

sub _compile_disabled
{
	my ($class) = @_;

	return sub {
		my ($compiler, $op, $context) = @_;

		$compiler->_invalid_script($op->[0]->name . ' is disabled');
	};
}

sub __checksig
{
	my ($runner, $sig, $hashtype, $raw_pubkey, $preimage) = @_;

	state $allowed_sighash = [
		SIGHASH_ALL,
		SIGHASH_ALL | SIGHASH_ANYONECANPAY,
		SIGHASH_SINGLE,
		SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
		SIGHASH_NONE,
		SIGHASH_NONE | SIGHASH_ANYONECANPAY,
	];

	if (defined $hashtype) {
		$runner->_invalid_script('bad sighash')
			if $runner->flags->strict_encoding
			&& none { $hashtype == $_ } @$allowed_sighash;

		$runner->_invalid_script('non-strict DER signature')
			if $runner->flags->strict_signatures
			&& !check_strict_der_signature($sig);
	}

	$runner->_invalid_script('non-strict pubkey')
		if $runner->flags->strict_encoding && !check_strict_public_key($raw_pubkey);

	my $pubkey;
	try {
		$pubkey = btc_pub->from_serialized($raw_pubkey)
	}
	catch ($e) {
		return !!0;
	}

	$runner->_script_error('public keys must be compressed')
		if $runner->flags->compressed_pubkeys
		&& $runner->transaction->is_segwit
		&& !$pubkey->compressed;

	return $pubkey->verify_message($preimage, $sig, flags => $runner->flags);
}

sub _OP_PUSHDATA
{
	my ($class, $opcode_name) = @_;

	return sub {
		my ($runner, $bytes) = @_;

		$runner->_invalid_script("push opcode for data is not minimal in $opcode_name")
			if $runner->flags->minimaldata && !standard_push($opcode_name, $bytes);

		push @{$runner->stack}, $bytes;
		$class->_verify_stack($runner);
	};
}

sub _OP_RESERVED
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		$runner->_invalid_script;
	};
}

# does nothing
sub _OP_NOP
{
	my ($class) = @_;

	return sub { };
}

sub _OP_NOP_UPGRADEABLE
{
	my ($class) = @_;

	return sub {
		my $runner = shift;

		$runner->_invalid_script('upgradeable NOP encountered')
			if $runner->flags->illegal_upgradeable_nops;
	};
}

sub _OP_VER
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		$runner->_invalid_script;
	};
}

sub _OP_IF
{
	my ($class, $inverted) = @_;

	return sub {
		my ($runner, $next_else_or_endif) = @_;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		my $value = pop @$stack;

		my $minimalif = $runner->is_tapscript
			|| ($runner->has_transaction && $runner->transaction->is_segwit && $runner->flags->minimalif);

		$value = $minimalif ? $runner->to_minimal_bool($value) : $runner->to_bool($value);
		$runner->_invalid_script('OP_IF argument is not minimal') unless defined $value;

		$value = !$value if $inverted;

		$runner->_set_pos($next_else_or_endif)
			unless $value;
	}
}

# should only get called when IF branch ops are depleted
sub _OP_ELSE
{
	my ($class) = @_;

	return sub {
		my ($runner, $next_else_or_endif) = @_;

		$runner->_set_pos($next_else_or_endif);
	};
}

# should only get called when IF or ELSE branch ops are depleted
# nothing to do here, will step to the next op
sub _OP_ENDIF
{
	my ($class) = @_;

	return $class->_OP_NOP;
}

sub _OP_VERIFY
{
	my ($class) = @_;

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
	my ($class) = @_;

	return sub {
		my $runner = shift;
		$runner->_invalid_script;
	};
}

sub _OP_TOALTSTACK
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @{$runner->alt_stack}, pop @$stack;
	};
}

sub _OP_FROMALTSTACK
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $alt = $runner->alt_stack;

		$runner->_stack_error unless @$alt >= 1;
		push @{$runner->stack}, pop @$alt;
	};
}

sub _OP_2DROP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		splice @$stack, -2, 2;
	};
}

sub _OP_2DUP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, @$stack[-2, -1];
		$class->_verify_stack($runner);
	};
}

sub _OP_3DUP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 3;
		push @$stack, @$stack[-3, -2, -1];
		$class->_verify_stack($runner);
	};
}

sub _OP_2OVER
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 4;
		push @$stack, @$stack[-4, -3];
		$class->_verify_stack($runner);
	};
}

sub _OP_2ROT
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 6;
		push @$stack, splice @$stack, -6, 2;
	};
}

sub _OP_2SWAP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 4;
		push @$stack, splice @$stack, -4, 2;
	};
}

sub _OP_IFDUP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		if ($runner->to_bool($stack->[-1])) {
			push @$stack, $stack->[-1];
			$class->_verify_stack($runner);
		}
	};
}

sub _OP_DEPTH
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		push @$stack, $runner->from_int(scalar @$stack);
		$class->_verify_stack($runner);
	};
}

sub _OP_DROP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		pop @$stack;
	};
}

sub _OP_DUP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $stack->[-1];
		$class->_verify_stack($runner);
	};
}

sub _OP_NIP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		splice @$stack, -2, 1;
	};
}

sub _OP_OVER
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, $stack->[-2];
		$class->_verify_stack($runner);
	};
}

sub _OP_PICK
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;

		my $n = $runner->to_int(pop @$stack);
		$runner->_stack_error if $n < 0 || $n >= @$stack;

		push @$stack, $stack->[-1 * ($n + 1)];
		$class->_verify_stack($runner);
	};
}

sub _OP_ROLL
{
	my ($class) = @_;

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
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 3;
		push @$stack, splice @$stack, -3, 1;
	};
}

sub _OP_SWAP
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		push @$stack, splice @$stack, -2, 1;
	};
}

sub _OP_TUCK
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 2;
		splice @$stack, -2, 0, $stack->[-1];
	};
}

sub _OP_SIZE
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int(length $stack->[-1]);
		$class->_verify_stack($runner);
	};
}

sub _OP_EQUAL
{
	my ($class) = @_;

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
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int($runner->to_int(pop @$stack) + 1);
	};
}

sub _OP_1SUB
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int($runner->to_int(pop @$stack) - 1);
	};
}

sub _OP_NEGATE
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int($runner->to_int(pop @$stack) * -1);
	};
}

sub _OP_ABS
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_int(abs $runner->to_int(pop @$stack));
	};
}

sub _OP_NOT
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_bool($runner->to_int(pop @$stack) == 0);
	};
}

sub _OP_0NOTEQUAL
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, $runner->from_bool($runner->to_int(pop @$stack) != 0);
	};
}

sub _OP_ADD
{
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

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
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, ripemd160(pop @$stack);
	};
}

sub _OP_SHA1
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, sha1(pop @$stack);
	};
}

sub _OP_SHA256
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, sha256(pop @$stack);
	};
}

sub _OP_HASH160
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, hash160(pop @$stack);
	};
}

sub _OP_HASH256
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		push @$stack, hash256(pop @$stack);
	};
}

sub _OP_CODESEPARATOR
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		$runner->_register_codeseparator;
	};
}

sub _OP_CHECKSIG
{
	my ($class) = @_;

	return sub {
		my $runner = shift;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 2;

		my $raw_pubkey = pop @$stack;
		my $sig = pop @$stack;
		my $sig_orig = $sig;

		my $hashtype = unpack 'C', substr $sig, -1, 1, '';

		my $preimage = $runner->transaction->get_digest(
			signatures => [$sig_orig],
			sighash => $hashtype,
		);

		my $result = __checksig($runner, $sig, $hashtype, $raw_pubkey, $preimage);

		$runner->_script_error('non-empty signature verification failed')
			if !$result && $runner->flags->nullfail && $sig ne '';

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
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $stack = $runner->stack;

		$runner->_stack_error unless @$stack >= 1;
		my $pubkeys_num = $runner->to_int(pop @$stack);
		$runner->_stack_error unless @$stack >= $pubkeys_num;
		$runner->_script_error('OP_CHECKMULTISIG maximum number of public keys exceeded')
			if $pubkeys_num > SCRIPT_MAX_MULTISIG_PUBKEYS;
		$runner->_increment_opcode_count($pubkeys_num);
		my @pubkeys = $pubkeys_num ? splice @$stack, -$pubkeys_num : ();

		$runner->_stack_error unless @$stack >= 1;
		my $signatures_num = $runner->to_int(pop @$stack);
		$runner->_stack_error unless @$stack >= $signatures_num;
		$runner->_script_error('OP_CHECKMULTISIG number of signatures exceeds the number of public keys')
			if $signatures_num > $pubkeys_num;
		my @signatures = $signatures_num ? splice @$stack, -$signatures_num : ();
		my @signatures_left = @signatures;

		# Remove extra unused value from the stack
		$runner->_stack_error unless @$stack >= 1;
		my $unused = pop @$stack;
		$runner->_script_error('OP_CHECKMULTISIG dummy argument must be empty')
			if $runner->flags->nulldummy && length $unused;

		my $found = !!1;
		my %digests;
		while (defined(my $sig = pop @signatures_left)) {
			my $hashtype = unpack 'C', substr $sig, -1, 1, '';

			my $preimage = $digests{$hashtype // ''} //= $runner->transaction->get_digest(
				signatures => [@signatures],
				sighash => $hashtype,
			);

			$found = !!0;
			while (defined(my $raw_pubkey = pop @pubkeys)) {
				$found = __checksig($runner, $sig, $hashtype, $raw_pubkey, $preimage);
				last if $found || @signatures_left + 1 > @pubkeys;
			}

			last if !$found;
		}

		# checking is correct if we have no more signatures to check and the
		# last one was found correctly
		my $result = $found && !@signatures_left;
		$runner->_script_error('non-empty signature verification failed')
			if !$result && $runner->flags->nullfail && notall { $_ eq '' } @signatures;

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
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $transaction = $runner->transaction;

		# NOP if no consensus rule
		return unless $runner->flags->checklocktimeverify;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 1;

		my $c1 = $runner->to_int($stack->[-1], 5);
		my $c2 = $runner->transaction->locktime;

		$runner->_invalid_script('negative number')
			if $c1 < 0;

		my $c1_is_height = $c1 < LOCKTIME_HEIGHT_THRESHOLD;
		my $c2_is_height = $c2 < LOCKTIME_HEIGHT_THRESHOLD;

		$runner->_invalid_script('type mismatch')
			unless !!$c1_is_height == !!$c2_is_height;

		$runner->_invalid_script
			if $c1 > $c2;

		$runner->_invalid_script('maximum sequence in input')
			if $transaction->this_input->sequence_no == MAX_SEQUENCE_NO;
	};
}

sub _OP_CHECKSEQUENCEVERIFY
{
	my ($class) = @_;

	return sub {
		my $runner = shift;
		my $transaction = $runner->transaction;

		# NOP if no consensus rule
		return unless $runner->flags->checksequenceverify;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 1;

		my $c1 = $runner->to_int($stack->[-1], 5);

		$runner->_invalid_script('negative number')
			if $c1 < 0;

		if (!($c1 & (1 << 31))) {
			$runner->_invalid_script('bad transaction version')
				if $transaction->version < 2;

			my $c2 = $transaction->this_input->sequence_no;

			$runner->_invalid_script("no mask in input's sequence")
				if $c2 & (1 << 31);

			my $c1_is_time = $c1 & (1 << 22);
			my $c2_is_time = $c2 & (1 << 22);

			$runner->_invalid_script('type mismatch')
				if !!$c1_is_time ne !!$c2_is_time;

			$runner->_invalid_script
				if ($c1 & 0x0000ffff) > ($c2 & 0x0000ffff);
		}
	};
}

sub _build_opcodes
{
	my ($class) = @_;

	my %opcodes = (
		OP_0 => {
			code => 0x00,
			pushop => !!1,
			on_compilation => $class->_compile_OP_NUM(0),
			runner => $class->_OP_PUSHDATA,
		},
		OP_PUSHDATA1 => {
			code => 0x4c,
			pushop => !!1,
			on_compilation => $class->_compile_OP_PUSHDATA(1),
			runner => $class->_OP_PUSHDATA('OP_PUSHDATA1'),
		},
		OP_PUSHDATA2 => {
			code => 0x4d,
			pushop => !!1,
			on_compilation => $class->_compile_OP_PUSHDATA(2),
			runner => $class->_OP_PUSHDATA('OP_PUSHDATA2'),
		},
		OP_PUSHDATA4 => {
			code => 0x4e,
			pushop => !!1,
			on_compilation => $class->_compile_OP_PUSHDATA(4),
			runner => $class->_OP_PUSHDATA('OP_PUSHDATA4'),
		},
		OP_1NEGATE => {
			code => 0x4f,
			pushop => !!1,
			on_compilation => $class->_compile_OP_NUM(-1),
			runner => $class->_OP_PUSHDATA,
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
			on_compilation => $class->_compile_OP_IF,
			runner => $class->_OP_IF,
		},
		OP_NOTIF => {
			code => 0x64,
			on_compilation => $class->_compile_OP_IF,
			runner => $class->_OP_IF(!!1),
		},
		OP_VERIF => {
			code => 0x65,
			on_compilation => $class->_compile_OP_VERIF,
		},
		OP_VERNOTIF => {
			code => 0x66,
			on_compilation => $class->_compile_OP_VERIF,
		},
		OP_ELSE => {
			code => 0x67,
			on_compilation => $class->_compile_OP_ELSE,
			runner => $class->_OP_ELSE,
		},
		OP_ENDIF => {
			code => 0x68,
			on_compilation => $class->_compile_OP_ENDIF,
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
		OP_CAT => {
			code => 0x7e,
			on_compilation => $class->_compile_disabled,
		},
		OP_SUBSTR => {
			code => 0x7f,
			on_compilation => $class->_compile_disabled,
		},
		OP_LEFT => {
			code => 0x80,
			on_compilation => $class->_compile_disabled,
		},
		OP_RIGHT => {
			code => 0x81,
			on_compilation => $class->_compile_disabled,
		},
		OP_SIZE => {
			code => 0x82,
			runner => $class->_OP_SIZE,
		},
		OP_INVERT => {
			code => 0x83,
			on_compilation => $class->_compile_disabled,
		},
		OP_AND => {
			code => 0x84,
			on_compilation => $class->_compile_disabled,
		},
		OP_OR => {
			code => 0x85,
			on_compilation => $class->_compile_disabled,
		},
		OP_XOR => {
			code => 0x86,
			on_compilation => $class->_compile_disabled,
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
		OP_2MUL => {
			code => 0x8d,
			on_compilation => $class->_compile_disabled,
		},
		OP_2DIV => {
			code => 0x8e,
			on_compilation => $class->_compile_disabled,
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
		OP_MUL => {
			code => 0x95,
			on_compilation => $class->_compile_disabled,
		},
		OP_DIV => {
			code => 0x96,
			on_compilation => $class->_compile_disabled,
		},
		OP_MOD => {
			code => 0x97,
			on_compilation => $class->_compile_disabled,
		},
		OP_LSHIFT => {
			code => 0x98,
			on_compilation => $class->_compile_disabled,
		},
		OP_RSHIFT => {
			code => 0x99,
			on_compilation => $class->_compile_disabled,
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
			sigop => !!1,
			runner => $class->_OP_CHECKSIG,
		},
		OP_CHECKSIGVERIFY => {
			code => 0xad,
			needs_transaction => !!1,
			sigop => !!1,
			runner => $class->_OP_CHECKSIGVERIFY
		},
		OP_CHECKMULTISIG => {
			code => 0xae,
			needs_transaction => !!1,
			sigop => !!1,
			runner => $class->_OP_CHECKMULTISIG,
		},
		OP_CHECKMULTISIGVERIFY => {
			code => 0xaf,
			needs_transaction => !!1,
			sigop => !!1,
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
			pushop => !!1,
			on_compilation => $class->_compile_OP_PUSH($num),
			runner => $class->_OP_PUSHDATA('OP_PUSH'),
		};
	}

	for my $num (1 .. 16) {
		$opcodes{"OP_$num"} = {
			code => 0x50 + $num,
			pushop => !!1,
			on_compilation => $class->_compile_OP_NUM($num),
			runner => $class->_OP_PUSHDATA,
		};
	}

	for my $num (1, 4 .. 10) {
		$opcodes{"OP_NOP$num"} = {
			code => 0xaf + $num,
			runner => $class->_OP_NOP_UPGRADEABLE,
		};
	}

	# aliases - prefixed with underscore
	$opcodes{_OP_FALSE} = $opcodes{OP_0};
	$opcodes{_OP_TRUE} = $opcodes{OP_1};

	return %opcodes;
}

sub opcodes
{
	my ($class) = @_;

	state $maps = {};
	return $maps->{$class} //= do {
		my %opcodes = $class->_build_opcodes;
		+{
			map {
				my $name = $_;
				$name =~ s/^_//;
				$_, $class->new(name => $name, %{$opcodes{$_}})
			} keys %opcodes
		};
	};
}

sub opcodes_reverse
{
	my ($class) = @_;

	state $maps = {};
	return $maps->{$class} //= do {
		my %codes = %{$class->opcodes};
		+{map { $codes{$_}{code}, $codes{$_} } grep { $_ !~ /^_/ } keys %codes};
	};
}

# this is how Bitcoin Core classifies opcodes as "push opcode"
sub non_push_opcode
{
	$_[0]->code > 0x60;
}

sub execute
{
	my ($self, @args) = @_;

	die_no_trace $self->name . ' is not implemented'
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

The code of the opcode - an 8-bit unsigned integer.

=head3 runner

A coderef which can be used to execute this opcode.

=head2 Methods

=head3 execute

Executes this opcode. Internal use only.

=head1 SEE ALSO

L<Bitcoin::Crypto::Script>

