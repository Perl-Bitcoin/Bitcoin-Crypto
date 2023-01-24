package Bitcoin::Crypto::Script::Runner;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;

use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Types qw(ArrayRef Str PositiveOrZeroInt);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(new_bigint pad_hex);

use namespace::clean;

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

sub to_int
{
	my ($self, $bytes) = @_;

	return 0 if !length $bytes;

	my $negative = !!0;
	my $last = substr $bytes, -1, 1;
	my $ord = ord $last;
	if ($ord >= 0x80) {
		$negative = !!1;
		substr $bytes, -1, 1, chr($ord - 0x80);
	}

	my $value = new_bigint(scalar reverse $bytes);
	$value->bneg if $negative;

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

sub from_bool
{
	my ($self, $value) = @_;

	return !!$value ? "\x01" : "\x00";
}

sub _advance
{
	my ($self, $count) = @_;
	$count //= 1;

	$self->_set_pos($self->pos + $count);
	return;
}

sub execute
{
	my ($self, $script, $initial_stack) = @_;

	$self->start($script, $initial_stack);
	1 while $self->step;

	return $self;
}

sub start
{
	my ($self, $script, $initial_stack) = @_;

	Bitcoin::Crypto::Exception::ScriptExecute->raise(
		'invalid argument passed to script runner, not a script instance'
	) unless blessed $script && $script->isa('Bitcoin::Crypto::Script');

	$self->_set_stack($initial_stack // []);
	$self->_set_alt_stack([]);
	$self->_set_pos(0);
	$self->_set_operations($script->operations);

	return $self;
}

sub step
{
	my ($self) = @_;

	my $pos = $self->pos;

	return !!0
		unless defined $pos;

	return !!0
		unless $pos < @{$self->operations};

	my ($op, @args) = @{$self->operations->[$pos]};

	Bitcoin::Crypto::Exception::ScriptRuntime->trap_into(
		sub {
			$op->execute($self, @args);
		},
		sub {
			"error at pos $pos (" . $op->name . "): $_"
		}
	);

	$self->_advance;
	return !!1;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Script::Runner - Bitcoin script runner

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

=head3 stack

Array reference - the stack which is used during script execution. Last item in
this array is the stack top. Use C<< $runner->stack->[-1] >> to examine the stack top.

Each item on the stack is a byte string. Use L</to_int> and L</to_bool> to
transform it into an integer or boolean value in the same fashion bitcoin
script interpreter does it.

=head3 alt_stack

Array reference - alt stack, used by C<OP_TOALTSTACK> and C<OP_FROMALTSTACK>.

=head3 operations

Array reference - An array of operations to be executed. Same as
L<Bitcoin::Crypto::Script/operations> and automatically obtained by calling it.

=head3 pos

Positive integer - the position of the operation to be run in the next step
(from L</operations>).

=head2 Methods

=head3 execute

	my $runner = $runner->execute($script, $initial_stack = []);

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

=head3 start

	my $runner = $runner->start($script, $initial_stack = []);

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

=head2 Helper methods

=head3 to_int, from_int

	my $int = $runner->to_int($byte_vector);
	my $byte_vector = $runner->from_int($int);

These methods encode and decode numbers in format which is used on L</stack>.

BigInts are used. C<to_int> will return an instance of L<Math::BigInt>, while
C<from_int> can accept it (but it should also handle regular numbers just
fine).

=head3 to_bool, from_bool

These methods encode and decode booleans in format which is used on L</stack>.

=head1 CAVEATS

Not all opcodes are implemented. An example of unimplemented opcode is
C<OP_CHECKLOCKTIMEVERIFY>, which would require access to transaction data.

OP_0 and OP_FALSE push byte vector C<0x00> to the stack, not null-size byte
vector.

There is curretly no limit on the size of byte vector which is going to be
transformed to an integer for ops like OP_ADD. BigInts are used for all integers.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * ScriptRuntime - script has encountered a runtime exception - the transaction is invalid

=item * ScriptSyntax - script syntax is invalid

=back

=head1 SEE ALSO

L<Bitcoin::Crypto::Script>

