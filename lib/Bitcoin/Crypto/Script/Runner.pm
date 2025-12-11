package Bitcoin::Crypto::Script::Runner;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;

use Scalar::Util qw(blessed);
use List::Util qw(any);

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(pad_hex ensure_length standard_push die_no_trace);
use Bitcoin::Crypto::Script::Transaction;
use Bitcoin::Crypto::Transaction::Flags;
use Bitcoin::Crypto::Constants qw(:script USE_BIGINTS);

has field 'script' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script'],
	writer => 1,
);

has option 'transaction' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Script::Transaction'])
		->plus_coercions(
			InstanceOf ['Bitcoin::Crypto::Transaction'],
			q{Bitcoin::Crypto::Script::Transaction->new(transaction => $_)}
		),
	trigger => 1,
	writer => 1,
	clearer => 1,
);

has param 'flags' => (
	coerce => (InstanceOf ['Bitcoin::Crypto::Transaction::Flags'])
		->plus_coercions(
			Undef, q{Bitcoin::Crypto::Transaction::Flags->new}
		),
	writer => 1,
	default => undef,
);

has field 'stack' => (
	isa => ArrayRef [ByteStr],
	writer => -hidden,
);

has field 'alt_stack' => (
	isa => ArrayRef [ByteStr],
	writer => -hidden,
);

has field 'pos' => (
	isa => PositiveOrZeroInt,
	writer => -hidden,
);

has field 'codeseparator' => (
	isa => PositiveOrZeroInt,
	writer => -hidden,
	clearer => -hidden,
);

has field '_opcode_count' => (
	isa => Int,
	writer => 1,
);

# shortcuts for quick access
sub _compiler { $_[0]->script->_compiler }
sub operations { $_[0]->_compiler->operations }

sub _trigger_transaction
{
	my ($self) = @_;

	$self->transaction->set_runner($self);
}

sub _stack_error
{
	die_no_trace 'stack error';
}

sub _invalid_script
{
	my ($self, $msg) = @_;
	$msg = defined $msg ? ": $msg" : '';

	$self->_script_error('transaction was marked as invalid' . $msg);
}

sub _script_error
{
	my ($self, $error) = @_;

	Bitcoin::Crypto::Exception::TransactionScript->raise($error);
}

sub to_int
{
	my ($self, $bytes, $max_bytes) = @_;
	$max_bytes //= 4;

	# too big vector cannot be interpreted as a number - see CScriptNum
	die_no_trace 'script numeric value too big to be interpreted as a number'
		if length $bytes > $max_bytes;

	return 0 if !length $bytes;

	my $negative = !!0;
	my $last = substr $bytes, -1, 1;
	my $ord = ord $last;
	if ($ord >= 0x80) {
		$negative = !!1;
		substr $bytes, -1, 1, chr($ord - 0x80);
	}

	my $value;
	if (USE_BIGINTS) {
		$value = Math::BigInt->from_bytes(scalar reverse $bytes);
		$value->bneg if $negative;
	}
	else {
		my $bytes = ensure_length scalar(reverse $bytes), 8;
		my ($higher, $lower) = unpack 'NN', $bytes;
		$value = ($higher << 32) + $lower;
		$value = -$value if $negative;
	}

	die_no_trace 'number is not minimally encoded'
		if ref $self && $self->flags->minimal_data && $bytes ne $self->from_int($value);

	return $value;
}

sub from_int
{
	my ($self, $value) = @_;

	my $bytes;
	my $negative;
	if (USE_BIGINTS) {
		if (!blessed $value) {
			$value = Math::BigInt->new($value);
		}

		return '' if $value == 0;

		$negative = $value < 0;
		$value->babs if $negative;

		$bytes = reverse pack 'H*', pad_hex($value->to_hex);
	}
	else {
		return '' if $value == 0;
		$negative = $value < 0;
		$value = abs $value if $negative;

		$bytes = pack 'V', $value & 0xffffffff;
		$bytes .= pack 'V', $value >> 32;

		$bytes =~ s/\x00+$//;
	}

	my $last = substr $bytes, -1, 1;
	my $ord = ord $last;
	if ($ord >= 0x80) {
		if ($negative) {
			$bytes .= "\x80";
		}
		else {
			$bytes .= "\x00";
		}
	}
	elsif ($negative) {
		substr $bytes, -1, 1, chr($ord + 0x80);
	}

	return $bytes;
}

sub to_bool
{
	my ($self, $bytes) = @_;
	$bytes //= '';

	my $len = length $bytes;
	return !!0 if $len == 0;

	my $substr = "\x00" x ($len - 1);
	return $bytes ne $substr . "\x00"
		&& $bytes ne $substr . "\x80";
}

sub to_minimal_bool
{
	my ($self, $bytes) = @_;
	$bytes //= '';

	return undef unless $bytes eq "\x01" or $bytes eq '';
	return length $bytes == 1;
}

sub from_bool
{
	my ($self, $value) = @_;

	return !!$value ? "\x01" : '';
}

sub _register_codeseparator
{
	my ($self) = @_;

	$self->_set_codeseparator($self->pos);
	return;
}

sub _increment_opcode_count
{
	my ($self, $number) = @_;

	# numify from bigint
	$number = "$number";

	$self->_set_opcode_count($self->_opcode_count + $number);

	$self->_script_error('script non-push opcode count exceeded')
		if !$self->is_tapscript
		&& $self->_opcode_count > SCRIPT_MAX_OPCODES;
}

sub stack_serialized
{
	my ($self) = @_;

	return join '',
		map { length $_ == 0 ? "\x00" : $_ }
		@{$self->stack};
}

signature_for execute => (
	method => !!1,
	positional => [BitcoinScript, ArrayRef [ByteStr], {default => []}],
);

sub execute
{
	my ($self, $script, $initial_stack) = @_;

	$self->start($script, $initial_stack);
	if (!$self->success) {
		my $stepper = $self->_step;

		# optimization: a lot of operations may want to check bytestrings here, but
		# all bytestrings were already checked and accepted
		local $Bitcoin::Crypto::Types::CHECK_BYTESTRINGS = !!0;

		1 while $stepper->();
	}

	return $self;
}

signature_for start => (
	method => !!1,
	positional => [BitcoinScript, ArrayRef [ByteStr], {default => []}],
);

sub start
{
	my ($self, $script, $initial_stack) = @_;

	$self->set_script($script);
	$self->_set_alt_stack([]);
	$self->_set_pos(0);
	$self->_clear_codeseparator;

	my $compiler = $self->_compiler;
	my $is_tapscript = $self->is_tapscript;
	$compiler->assert_valid;

	Bitcoin::Crypto::Exception::ScriptRuntime->raise(
		'cannot run tapscript without taproot flag'
	) if $is_tapscript && !$self->flags->taproot;

	# set and increment opcode count. Incrementing is checking for too many
	# opcodes (SCRIPT_MAX_OPCODES)
	$self->_set_opcode_count(0);
	$self->_increment_opcode_count($compiler->opcode_count // 0);

	# run this ONLY if the script was not marked as "unconditionally valid"
	if (!$compiler->unconditionally_valid) {
		Bitcoin::Crypto::Exception::ScriptRuntime->trap_into(
			sub {
				die_no_trace 'script size exceeded'
					if !$is_tapscript
					&& length $script->to_serialized > SCRIPT_MAX_SIZE;

				die_no_trace 'maximum stack element size exceeded'
					if any { $_->[0]->pushop && length $_->[2] > SCRIPT_MAX_ELEMENT_SIZE } @{$self->operations};
			}
		);

		Bitcoin::Crypto::Exception::ScriptPush->trap_into(
			sub {
				die_no_trace 'maximum initial stack element count exceeded'
					if $is_tapscript && @$initial_stack > SCRIPT_MAX_STACK_ELEMENTS;

				die_no_trace 'maximum initial stack element size exceeded'
					if any { length $_ > SCRIPT_MAX_ELEMENT_SIZE } @$initial_stack;

				$self->_set_stack($initial_stack);
			}
		);
	}

	return $self;
}

sub _step
{
	my ($self) = @_;

	# if pos is undefined, execution was not yet started
	my $pos = $self->pos;
	return sub { !!0 }
		unless defined $pos;

	my $operations = $self->operations;
	my $has_transaction = $self->has_transaction;

	return sub {
		my $compiled_op = $operations->[$pos];

		# out of operations
		return !!0 unless defined $compiled_op;
		my ($op, $raw_op, @args) = @{$compiled_op};

		Bitcoin::Crypto::Exception::TransactionScript->raise(
			'no transaction is set for the script runner'
		) if $op->needs_transaction && !$has_transaction;

		Bitcoin::Crypto::Exception::ScriptRuntime->trap_into(
			sub {
				$op->execute($self, @args);
			},
			"error at pos $pos (" . $op->name . ")"
		);

		# cannot trust $pos anymore. Jumps in script could've happened
		$pos = $self->pos + 1;
		$self->_set_pos($pos);
		return !!1;
	};
}

sub step
{
	my ($self) = @_;

	return $self->_step->();
}

sub subscript
{
	my ($self, $sigs) = @_;

	my $start = ($self->codeseparator // -1) + 1;
	my $operations = $self->operations;

	if ($self->transaction->this_input->is_segwit) {
		return join '', map { $_->[1] } @{$operations}[$start .. $#$operations];
	}
	else {
		my %sigs_lookup = map { $_ => 1 } grep { length $_ // '' } @{$sigs // []};

		my $result = '';
		foreach my $operation (@{$operations}[$start .. $#$operations]) {
			my ($op, $raw_op, $pushop_data) = @$operation;

			my $name = $op->name;
			next if $name eq 'OP_CODESEPARATOR';
			next if $op->pushop && $sigs_lookup{$pushop_data} && standard_push($name, $pushop_data);

			$result .= $raw_op;
		}

		if ($self->flags->const_script) {
			my $orig = $self->script->to_serialized;
			$self->_invalid_script('script is not constant')
				if $result ne $orig;
		}

		return $result;
	}
}

sub success
{
	my ($self) = @_;

	return !!1 if $self->_compiler->unconditionally_valid;
	return !!0 if $self->pos != @{$self->operations};

	my $stack = $self->stack;
	return !!0 if !$stack;
	return !!0 if !$stack->[-1];
	return !!0 if !$self->to_bool($stack->[-1]);

	# NOTE: clean_stack rule does not check altstack, because altstack can only
	# be manipulated by the script itself, so there is no chance for witness
	# malleability
	if (@$stack > 1) {
		my $segwit = $self->has_transaction && $self->transaction->is_native_segwit;
		return !!0 if $segwit || $self->is_tapscript || $self->flags->clean_stack;
	}

	return !!1;
}

sub is_tapscript
{
	my $script = shift->script;
	return $script && $script->isa('Bitcoin::Crypto::Tapscript');
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Script::Runner - Bitcoin Script runner

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script::Runner;
	use Data::Dumper;

	my $runner = Bitcoin::Crypto::Script::Runner->new;

	# provide an instance of Bitcoin::Crypto::Script
	# runs the script all at once
	$runner->execute($script);

	# ... or: runs the script step by step
	$runner->start($script);
	while ($runner->step) {
		print 'runner step, stack: ';
		print Dumper($runner->stack);
	}

	print 'FAILURE' unless $runner->success;
	print 'resulting stack: ';
	print Dumper($runner->stack);

=head1 DESCRIPTION

This class instances can be used to execute Bitcoin scripts defined as
instances of L<Bitcoin::Crypto::Script>. Scripts can be executed in one go or
step by step, and the execution stack is available through an accessor.

One runner can be used to execute scripts multiple times. Each time you call
C<execute> or C<start>, the runner state is reset. Initial stack state can be
provided to either one of those methods. This provides better control over
execution than L<Bitcoin::Crypto::Script/run>, which simply executes the script
and returns its stack.

=head1 INTERFACE

=head2 Attributes

=head3 transaction

Instance of L<Bitcoin::Crypto::Transaction> wrapped inside
C<Bitcoin::Crypto::Script::Transaction> for some extra data. It is optional,
but some opcodes will refuse to function without it.

I<predicate:> C<has_transaction>

I<writer:> C<set_transaction>

=head3 flags

An instance of L<Bitcoin::Crypto::Transaction::Flags>. If not passed, full set
of consensus flags will be assumed (same as calling
L<Bitcoin::Crypto::Transaction::Flags/new> with no arguments).

I<writer:> C<set_flags>

=head3 script

The current script being executed. Will be set automatically in L</start>.
C<set_script> can be used to set it manually.

B<Not assignable in the constructor>

=head3 stack

B<Not assignable in the constructor>

Array reference - the stack which is used during script execution. Last item in
this array is the stack top. Use C<< $runner->stack->[-1] >> to examine the stack top.

Each item on the stack is a byte string. Use L</to_int> and L</to_bool> to
transform it into an integer or boolean value in the same fashion bitcoin
script interpreter does it.

=head3 alt_stack

B<Not assignable in the constructor>

Array reference - alt stack, used by C<OP_TOALTSTACK> and C<OP_FROMALTSTACK>.

=head3 operations

B<Not assignable in the constructor>

A proxy to L<Bitcoin::Crypto::Script/operations> of the selected L</script>.

=head3 pos

B<Not assignable in the constructor>

Positive integer - the position of the operation to be run in the next step
(from L</operations>).

=head3 codeseparator

B<Not assignable in the constructor>

Positive integer - L</pos> of the last encountered codeseparator, or undef
if none was encountered.

=head2 Methods

=head3 new

	$object = $class->new(%data)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 execute

	$object = $object->execute($script, \@initial_stack = [])

Executes the script in one go. Returns runner instance (for chaining).

C<$script> must be an instance of L<Bitcoin::Crypto::Script>. If you only have
a serialized script in a string, call
L<Bitcoin::Crypto::Script/from_serialized> first to get a proper script
instance. C<$initial_stack> will be used to pre-populate the stack before
running the script.

After the method returns call L</stack> to get execution stack. This can be
done in a single line:

	my $stack = $runner->execute($script)->stack;

If errors occur, an exception will be thrown.

=head3 start

	$object = $object->start($script, \@initial_stack = [])

Same as L</execute>, but only sets initial runner state and does not actually
execute any script opcodes. L</step> must be called to continue the execution.

=head3 step

	while ($runner->step) {
		# do something after each step
	}

Executes the next script opcode. Returns a false value if the script finished
the execution, and a true value otherwise.

L</start> must be called before this method is called.

Note that not every opcode will take a step to execute. This means that this script:

	OP_1 OP_IF OP_PUSHDATA1 1 0x1f OP_ENDIF

will take four steps to execute (C<OP_1> -> C<OP_IF> -> C<0x1f> -> C<OP_ENDIF>).

This one however:

	OP_1 OP_IF OP_PUSHDATA1 1 0x1f OP_ELSE OP_PUSHDATA1 2 0xe15e OP_ENDIF

will also take four steps (C<OP_1> -> C<OP_IF> -> C<0x1f> -> C<OP_ELSE>).
This happens because C<OP_ELSE> performs a jump past C<OP_ENDIF>.
If the initial op was C<OP_0>, the execution would be C<OP_0> -> C<OP_IF> ->
C<0xe15e> -> C<OP_ENDIF>. No C<OP_ELSE> since it was jumped over and reaching
C<OP_ENDIF>.

These details should not matter usually, but may be confusing if you would
want to for example print your stack step by step. When in doubt, check C<<
$runner->pos >>, which contains the position of the B<next> opcode to execute.

=head3 subscript

	$subscript = $object->subscript()

Returns current subscript - part of the running script from after the last
codeseparator, also known as scriptCode.

Depending on the input spending segwit, the subscript will behave differently:

=over

=item * pre-segwit

Removes all codeseparators after the last executed codeseparator. B<Currently
does not remove the signature (known as FindAndDelete)>.

=item * segwit

Only removes the part up to the last executed C<OP_CODESEPARATOR>.

=back

=head3 success

	$boolean = $object->success()

Returns a boolean indicating whether the script execution was successful.

=head3 is_tapscript

	$boolean = $object->is_tapscript()

Returns true if currently executed script is a tapscript.

=head2 Helper methods

=head3 to_int

=head3 from_int

	my $int = $runner->to_int($byte_vector, $max_bytes = 4);
	my $byte_vector = $runner->from_int($int);

These methods encode and decode numbers in format which is used on L</stack>.

C<to_int> limits the size of an integer to C<$max_bytes>.

On 32-bit machines, BigInts are used. C<to_int> will return an instance of
L<Math::BigInt>, while C<from_int> can accept it (but it should also handle
regular numbers just fine). On 64-bit machines, perl numbers will be used.

Most of the time, the internal representation of integers on the stack should
not matter. If it does matter though, C<BITCOIN_CRYPTO_USE_BIGINTS>
environmental variable can be set to C<1> to force use of BigInts on 64 bit
machines.

=head3 to_bool

=head3 to_minimal_bool

=head3 from_bool

These methods encode and decode booleans in format which is used on L</stack>.
C<to_minimal_bool> variant is used to enforce L<Bitcoin::Crypto::Transaction::Flags/minimal_if>.

=head3 stack_serialized

Returns the serialized stack. Any null vectors will be transformed to C<0x00>.

=head1 SEE ALSO

L<Bitcoin::Crypto::Script>

