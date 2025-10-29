package Bitcoin::Crypto::Script::Runner;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Try::Tiny;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(pad_hex);
use Bitcoin::Crypto::Script::Transaction;

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
	writer => 1,
	clearer => 1,
);

has field 'stack' => (
	isa => ArrayRef [Str],
	writer => -hidden,
);

has field 'alt_stack' => (
	isa => ArrayRef [Str],
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

has field '_codeseparator' => (
	isa => PositiveOrZeroInt,
	writer => 1,
);

has field '_valid' => (
	isa => Bool,
	writer => 1,
	predicate => 1,
	clearer => 1,
);

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
	die "script numeric value $value out of range"
		if abs($value) > 2**($max_bytes * 8 - 1) - 1;

	return $value;
}

sub from_int
{
	my ($self, $value) = @_;

	if (!blessed $value) {
		$value = Math::BigInt->new($value);
	}

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
	$self->_set_stack($initial_stack);
	$self->_set_alt_stack([]);
	$self->_set_pos(0);
	$self->_register_codeseparator;
	$self->_clear_valid;

	try {
		Bitcoin::Crypto::Exception::ScriptCompilation->trap_into(
			sub {
				$self->compile;
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

	my $pos = $self->pos;

	return !!0
		unless defined $pos;

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
	positional => [],
);

sub subscript
{
	my ($self) = @_;
	my $start = $self->_codeseparator;
	my @operations = @{$self->operations};

	my $result = '';
	foreach my $operation (@operations[$start .. $#operations]) {
		my ($op, $raw_op) = @$operation;
		next if $op->name eq 'OP_CODESEPARATOR';
		$result .= $raw_op;
	}

	# NOTE: signature is not removed from the subscript, since runner doesn't know what it is

	return $result;
}

signature_for compile => (
	method => Object,
	positional => [],
);

sub compile
{
	my ($self) = @_;
	my $script = $self->script;

	my $serialized = $script->to_serialized;
	my @ops;

	my $data_push = sub {
		my ($size) = @_;

		Bitcoin::Crypto::Exception::ScriptSyntax->raise(
			'not enough bytes of data in the script'
		) if length $serialized < $size;

		return substr $serialized, 0, $size, '';
	};

	my %context = (
		op_if => undef,
		op_else => undef,
		previous_context => undef,
	);

	my %special_ops = (
		OP_PUSHDATA1 => sub {
			my ($op) = @_;
			my $raw_size = substr $serialized, 0, 1, '';
			my $size = unpack 'C', $raw_size;

			push @$op, $data_push->($size);
			$op->[1] .= $raw_size . $op->[2];
		},
		OP_PUSHDATA2 => sub {
			my ($op) = @_;
			my $raw_size = substr $serialized, 0, 2, '';
			my $size = unpack 'v', $raw_size;

			push @$op, $data_push->($size);
			$op->[1] .= $raw_size . $op->[2];
		},
		OP_PUSHDATA4 => sub {
			my ($op) = @_;
			my $raw_size = substr $serialized, 0, 4, '';
			my $size = unpack 'V', $raw_size;

			push @$op, $data_push->($size);
			$op->[1] .= $raw_size . $op->[2];
		},
		OP_IF => sub {
			my ($op) = @_;

			if ($context{op_if}) {
				%context = (
					previous_context => {%context},
				);
			}
			$context{op_if} = $op;
		},
		OP_ELSE => sub {
			my ($op, $pos) = @_;

			Bitcoin::Crypto::Exception::ScriptSyntax->raise(
				'OP_ELSE found but no previous OP_IF or OP_NOTIF'
			) if !$context{op_if};

			Bitcoin::Crypto::Exception::ScriptSyntax->raise(
				'multiple OP_ELSE for a single OP_IF'
			) if @{$context{op_if}} > 2;

			$context{op_else} = $op;

			push @{$context{op_if}}, $pos;
		},
		OP_ENDIF => sub {
			my ($op, $pos) = @_;

			Bitcoin::Crypto::Exception::ScriptSyntax->raise(
				'OP_ENDIF found but no previous OP_IF or OP_NOTIF'
			) if !$context{op_if};

			push @{$context{op_if}}, undef
				if @{$context{op_if}} == 2;
			push @{$context{op_if}}, $pos;

			if ($context{op_else}) {
				push @{$context{op_else}}, $pos;
			}

			if ($context{previous_context}) {
				%context = %{$context{previous_context}};
			}
			else {
				%context = ();
			}
		},
	);

	$special_ops{OP_NOTIF} = $special_ops{OP_IF};
	my @debug_ops;
	my $position = 0;

	try {
		while (length $serialized) {
			my $this_byte = substr $serialized, 0, 1, '';
			my $opcode;
			my @to_push;

			try {
				$opcode = $script->opcode_class->get_opcode_by_code(ord $this_byte);
				push @to_push, $this_byte;
			}
			catch {
				my $err = $_;

				my $opcode_num = ord($this_byte);
				unless ($opcode_num > 0 && $opcode_num <= 75) {
					push @debug_ops, unpack 'H*', $this_byte;
					die $err;
				}

				# NOTE: compiling standard data push into PUSHDATA1 for now
				$opcode = $script->opcode_class->get_opcode_by_name('OP_PUSHDATA1');
				$serialized = $this_byte . $serialized;
				push @to_push, '';
			};

			push @debug_ops, $opcode->name;
			unshift @to_push, $opcode;

			if ($opcode->has_on_compilation) {
				$opcode->on_compilation->($self, $opcode);
			}

			if (exists $special_ops{$opcode->name}) {
				$special_ops{$opcode->name}->(\@to_push, $position);
			}

			push @ops, \@to_push;
			$position += 1;
		}

		Bitcoin::Crypto::Exception::ScriptSyntax->raise(
			'some OP_IFs were not closed'
		) if $context{op_if};
	}
	catch {
		my $ex = $_;
		if (blessed $ex && $ex->isa('Bitcoin::Crypto::Exception::ScriptCompilation')) {
			$ex->set_script(\@debug_ops);
			$ex->set_error_position($position);
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
	return !!1;
}

signature_for tapscript => (
	method => Object,
	positional => [],
);

sub tapscript
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

Instance of L<Bitcoin::Crypto::Transaction>. It is optional, but some opcodes
will refuse to function without it.

I<predicate:> C<has_transaction>

I<writer:> C<set_transaction>

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
exception in case of both success and failure.

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
codeseparator, with all other codeseparators removed.

=head3 success

	$boolean = $object->success()

Returns a boolean indicating whether the script execution was successful.

=head3 tapscript

	$boolean = $object->tapscript()

Returns true if currently executed script is a tapscript.

=head2 Helper methods

=head3 to_int, from_int

	my $int = $runner->to_int($byte_vector);
	my $byte_vector = $runner->from_int($int);

These methods encode and decode numbers in format which is used on L</stack>.

BigInts are used. C<to_int> will return an instance of L<Math::BigInt>, while
C<from_int> can accept it (but it should also handle regular numbers just
fine).

=head3 to_bool, to_minimal_bool, from_bool

These methods encode and decode booleans in format which is used on L</stack>.
C<to_minimal_bool> variant is used to enforce MINIMALIF rule.

=head3 stack_serialized

Returns the serialized stack. Any null vectors will be transformed to C<0x00>.

=head1 CAVEATS

There is curretly no limit on the size of byte vector which is going to be
transformed to an integer for ops like OP_ADD. BigInts are used for all integers.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * ScriptRuntime - script has encountered a runtime exception - the transaction is invalid

=item * ScriptCompilation - script compilation has eccountered a problem

=back

=head1 SEE ALSO

L<Bitcoin::Crypto::Script>

