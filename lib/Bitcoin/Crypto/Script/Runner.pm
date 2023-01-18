package Bitcoin::Crypto::Script::Runner;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;

use Scalar::Util qw(blessed);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Digest::SHA1 qw(sha1);

use Bitcoin::Crypto::Types qw(ArrayRef Str PositiveOrZeroInt);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(new_bigint pad_hex hash160 hash256);

use namespace::clean;

has field 'stack' => (
	isa => ArrayRef[Str],
	writer => -hidden,
);

has field 'alt_stack' => (
	isa => ArrayRef[Str],
	writer => -hidden,
);

has field 'pos' => (
	isa => PositiveOrZeroInt,
	writer => -hidden,
);

has field 'operations' => (
	isa => ArrayRef[ArrayRef],
	writer => -hidden,
);

sub _toint
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

sub _fromint
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

sub _tobool
{
	my ($self, $bytes) = @_;

	my $len = length $bytes;
	return !!0 if $len == 0;

	my $substr = "\x00" x ($len - 1);
	return $bytes ne $substr . "\x00"
		&& $bytes ne $substr . "\x80";
}

sub _frombool
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

	Bitcoin::Crypto::Exception::ScriptRuntime->trap_into(sub {
		my ($op, @args) = @{$self->operations->[$pos]};

		$op->execute($self, @args);
	});

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

=head2 Fields

=head3 stack

=head3 alt_stack

=head3 pos

=head3 operations

=head2 Methods

=head3 execute

=head3 start

=head3 step

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

