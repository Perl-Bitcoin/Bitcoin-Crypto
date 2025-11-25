package Bitcoin::Crypto::Script::Runner;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Try::Tiny;
use Scalar::Util qw(blessed);
use List::Util qw(any);

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(pad_hex standard_push);
use Bitcoin::Crypto::Script::Transaction;
use Bitcoin::Crypto::Transaction::Flags;

use namespace::clean;

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

has field 'operations' => (
	isa => ArrayRef [ArrayRef],
	writer => -hidden,
);

has field 'codeseparator' => (
	isa => PositiveOrZeroInt,
	writer => -hidden,
	clearer => -hidden,
);

has field '_valid' => (
	isa => Bool,
	writer => 1,
	predicate => 1,
	clearer => 1,
);

sub _trigger_transaction
{
	my ($self) = @_;

	$self->transaction->set_runner($self);
}

sub _stack_error
{
	die 'stack error';
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

	return 0 if !length $bytes;

	my $negative = !!0;
	my $last = substr $bytes, -1, 1;
	my $ord = ord $last;
	if ($ord >= 0x80) {
		$negative = !!1;
		substr $bytes, -1, 1, chr($ord - 0x80);
	}

	my $value = Math::BigInt->from_bytes(scalar reverse $bytes);
	$value->bneg if $negative;

	# too big vector cannot be interpreted as a number - see CScriptNum
	die "script numeric value $value cannot be interpreted as a number"
		if length $bytes > $max_bytes;

	return $value;
}

sub from_int
{
	my ($self, $value) = @_;

	if (!blessed $value) {
		$value = Math::BigInt->new($value);
	}

	return '' if $value == 0;

	my $negative = $value < 0;
	$value->babs if $negative;

	my $bytes = reverse pack 'H*', pad_hex($value->to_hex);

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

	my $len = length $bytes;
	return !!0 if $len == 0;

	my $substr = "\x00" x ($len - 1);
	return $bytes ne $substr . "\x00"
		&& $bytes ne $substr . "\x80";
}

sub to_minimal_bool
{
	my ($self, $bytes) = @_;

	return undef unless $bytes eq "\x01" or $bytes eq '';
	return length $bytes == 1;
}

sub from_bool
{
	my ($self, $value) = @_;

	return !!$value ? "\x01" : '';
}

sub _advance
{
	my ($self, $count) = @_;
	$count //= 1;

	$self->_set_pos($self->pos + $count);
	return;
}

sub _register_codeseparator
{
	my ($self) = @_;

	$self->_set_codeseparator($self->pos);
	return;
}

signature_for stack_serialized => (
	method => Object,
	positional => [],
);

sub stack_serialized
{
	my ($self) = @_;

	return join '',
		map { length $_ == 0 ? "\x00" : $_ }
		@{$self->stack};
}

signature_for execute => (
	method => Object,
	positional => [BitcoinScript, ArrayRef [ByteStr], {default => []}],
);

sub execute
{
	my ($self, $script, $initial_stack) = @_;

	$self->start($script, $initial_stack);
	1 while $self->step;

	return $self;
}

signature_for start => (
	method => Object,
	positional => [BitcoinScript, ArrayRef [ByteStr], {default => []}],
);

sub start
{
	my ($self, $script, $initial_stack) = @_;

	$self->set_script($script);
	$self->_set_alt_stack([]);
	$self->_set_pos(0);
	$self->_clear_codeseparator;
	$self->_clear_valid;

	try {
		Bitcoin::Crypto::Exception::ScriptCompilation->trap_into(
			sub {
				die 'cannot run tapscript without taproot flag'
					if $self->is_tapscript && !$self->flags->taproot;

				$self->compile;
			}
		);

		Bitcoin::Crypto::Exception::ScriptPush->trap_into(
			sub {
				die 'maximum initial stack element size exceeded'
					if $self->is_tapscript && @$initial_stack > Bitcoin::Crypto::Constants::script_max_stack_elements;
				die 'maximum initial stack element size exceeded'
					if any { length $_ > Bitcoin::Crypto::Constants::script_max_element_size } @$initial_stack;

				$self->_set_stack($initial_stack);
			}
		);
	}
	catch {
		my $ex = $_;

		if ($ex->isa('Bitcoin::Crypto::Exception::ScriptSuccess')) {
			$self->_set_valid(!!1);
			$self->_set_operations([]);
		}
		else {
			die $ex;
		}
	};

	return $self;
}

signature_for step => (
	method => Object,
	positional => [],
);

sub step
{
	my ($self) = @_;

	# optimization: a lot of operations may want to check bytestrings here, but
	# all bytestrings were already checked and accepted
	local $Bitcoin::Crypto::Types::CHECK_BYTESTRINGS = !!0;

	my $pos = $self->pos;

	# execution not started
	return !!0
		unless defined $pos;

	# out of operations
	return !!0
		unless $pos < @{$self->operations};

	my ($op, $raw_op, @args) = @{$self->operations->[$pos]};

	Bitcoin::Crypto::Exception::Transaction->raise(
		'no transaction is set for the script runner'
	) if $op->needs_transaction && !$self->has_transaction;

	Bitcoin::Crypto::Exception::ScriptRuntime->trap_into(
		sub {
			$op->execute($self, @args);
		},
		"error at pos $pos (" . $op->name . ")"
	);

	$self->_advance;
	return !!1;
}

signature_for subscript => (
	method => Object,
	positional => [Maybe [ArrayRef [ByteStr]], {default => undef}],
);

sub subscript
{
	my ($self, $sigs) = @_;
	$sigs = [grep { length($_ // '') } @{$sigs // []}];

	my $start = ($self->codeseparator // -1) + 1;
	my @operations = @{$self->operations};

	my $witness = $self->transaction->this_input->is_segwit;

	my $result = '';
	foreach my $operation (@operations[$start .. $#operations]) {
		my ($op, $raw_op, $pushop_data) = @$operation;

		if (!$witness) {
			next if $op->name eq 'OP_CODESEPARATOR';
			next if $op->pushop && (any { $pushop_data eq $_ } @{$sigs}) && standard_push($op->name, $pushop_data);
		}

		$result .= $raw_op;
	}

	if (!$witness && $self->flags->const_script) {
		my $orig = $self->script->to_serialized;
		$self->_invalid_script('script is not constant')
			if $result ne $orig;
	}

	return $result;
}

signature_for compile => (
	method => Object,
	positional => [],
);

sub compile
{
	my ($self) = @_;
	my $opcode_class = $self->script->opcode_class;
	my @ops;
	my @debug_ops;

	my %context = (
		serialized => $self->script->to_serialized,
		position => 0,
	);

	try {
		while (length $context{serialized}) {
			my $this_byte = substr $context{serialized}, 0, 1, '';
			my $opcode;
			my @to_push;

			try {
				$opcode = $opcode_class->get_opcode_by_code(ord $this_byte);
				push @to_push, $this_byte;
			}
			catch {
				my $err = $_;
				push @debug_ops, unpack 'H*', $this_byte;
				die $err;
			};

			push @debug_ops, $opcode->name;
			unshift @to_push, $opcode;

			if ($opcode->has_on_compilation) {
				$opcode->on_compilation->($self, \@to_push, \%context);
			}

			push @ops, \@to_push;
			$context{position} += 1;
		}

		Bitcoin::Crypto::Exception::ScriptSyntax->raise(
			'some OP_IFs were not closed'
		) if $context{branch};
	}
	catch {
		my $ex = $_;
		if (blessed $ex && $ex->isa('Bitcoin::Crypto::Exception::ScriptCompilation')) {
			$ex->set_script(\@debug_ops);
			$ex->set_error_position($context{position});
		}

		die $ex;
	};

	$self->_set_operations(\@ops);
}

signature_for success => (
	method => Object,
	positional => [],
);

sub success
{
	my ($self) = @_;

	return $self->_valid if $self->_has_valid;

	my $stack = $self->stack;
	return !!0 if !$stack;
	return !!0 if !$stack->[-1];
	return !!0 if !$self->to_bool($stack->[-1]);

	# TODO: check altstack?
	if (@$stack > 1) {
		my $segwit = $self->has_transaction && $self->transaction->is_native_segwit;
		return !!0 if $segwit || $self->is_tapscript || $self->flags->cleanstack;
	}

	return !!1;
}

signature_for is_tapscript => (
	method => Object,
	positional => [],
);

sub is_tapscript
{
	my ($self) = @_;

	my $script = $self->script;
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

Array reference - An array of operations to be executed. Same as
L<Bitcoin::Crypto::Script/operations> and automatically obtained by calling it.

	[
		[OP_XXX (Object), raw (String), ...],
		...
	]

The first element of each subarray is the L<Bitcoin::Crypto::Script::Opcode>
object. The second element is the raw opcode string, usually single byte. The
rest of elements are metadata and is dependant on the op type. This metadata is
used during script execution.

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

If errors occur, they will be thrown as exceptions. See L</EXCEPTIONS>.

=head3 compile

	$object->compile()

Fills L</operations> based on the contents of L</script>. May throw an
exception in case of both success and failure. Advanced use only.

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

=head3 to_int, from_int

	my $int = $runner->to_int($byte_vector, $max_bytes = 4);
	my $byte_vector = $runner->from_int($int);

These methods encode and decode numbers in format which is used on L</stack>.

BigInts are used. C<to_int> will return an instance of L<Math::BigInt>, while
C<from_int> can accept it (but it should also handle regular numbers just
fine). C<to_int> limits the size of an integer to C<$max_bytes>.

=head3 to_bool, to_minimal_bool, from_bool

These methods encode and decode booleans in format which is used on L</stack>.
C<to_minimal_bool> variant is used to enforce MINIMALIF rule.

=head3 stack_serialized

Returns the serialized stack. Any null vectors will be transformed to C<0x00>.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * ScriptRuntime - script has encountered a runtime exception - the transaction is invalid

=item * ScriptCompilation - script compilation has encountered a problem

=back

=head1 SEE ALSO

L<Bitcoin::Crypto::Script>

