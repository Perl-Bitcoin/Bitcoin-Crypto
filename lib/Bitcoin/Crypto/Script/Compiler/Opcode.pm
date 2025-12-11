package Bitcoin::Crypto::Script::Compiler::Opcode;

use v5.14;
use warnings;

sub new
{
	my ($class, $opcode, $raw) = @_;

	return bless [$opcode, $raw], $class;
}

sub opcode
{
	return $_[0][0];
}

sub raw_data
{
	return $_[0][1];
}

sub push_data
{
	return $_[0][0]->pushop ? $_[0][2] : undef;
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Script::Compiler::Opcode - Compiled script opcode

=head1 SYNOPSIS

	my $ops = $script->operations;
	foreach my $op (@{$ops}) {
		say $op->opcode->name;
	}

=head1 DESCRIPTION

This class represents a compiled opcode. It wraps
L<Bitcoin::Crypto::Script::Opcode> along with some more data pulled out of a
script.

Bitcoin::Crypto used to return plain array references as compiled opcode in the
past. This class preserves the old method of access through an array reference,
as well as introduces a convenience layer on top of it.

=head1 INTERFACE

=head2 Methods

=head3 new

Constructor is internal and advanced use only. You should not create objects of
this class yourself, as they are only valid if they came from compiling a
script.

=head3 opcode

	$opcode = $object->opcode()

Returns an instance of L<Bitcoin::Crypto::Script::Opcode> for this operation.

=head3 raw_data

	$bytes = $object->raw_data()

Returns a bytestring containing the raw operation. For non-push opcodes, this
will be the same as L<Bitcoin::Crypto::Script::Opcode/code>, but packed into a
byte. For push opcodes, this is the opcode code plus all the data they contain.

=head3 push_data

	$bytes = $object->push_data()

Returns a bytestring containing bytes pushed onto the stack by the push
operation. If this operation is not a push operation, returns undef.

