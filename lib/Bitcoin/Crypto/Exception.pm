package Bitcoin::Crypto::Exception;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Try::Tiny;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Types qw(Str Maybe ArrayRef);

use namespace::clean;

use overload
	q{""} => "as_string",
	fallback => 1;

has param 'message' => (
	isa => Str,
	writer => -hidden,
);

has field 'caller' => (
	isa => Maybe [ArrayRef],
	default => sub {
		for my $call_level (1 .. 20) {
			my ($package, $file, $line) = caller $call_level;
			if (defined $package && $package !~ /^(Bitcoin::Crypto|Try::Tiny|Type::Coercion)/) {
				return [$package, $file, $line];
			}
		}
		return undef;
	},
);

sub raise
{
	my ($self, $error) = @_;

	if (defined $error) {
		$self = $self->new(message => $error);
	}

	die $self;
}

sub throw
{
	goto \&raise;
}

sub trap_into
{
	my ($class, $sub, $prefix) = @_;

	my $ret;
	try {
		$ret = $sub->();
	}
	catch {
		my $ex = $_;

		if (blessed $ex) {
			if ($ex->isa($class)) {
				$ex->_set_message("$prefix: " . $ex->message)
					if $prefix;

				$ex->raise;
			}

			if ($ex->isa('Bitcoin::Crypto::Exception')) {
				$class->raise(($prefix ? "$prefix: " : '') . $ex->message);
			}
		}

		$class->raise($prefix ? "$prefix: $ex" : "$ex");
	};

	return $ret;
}

sub as_string
{
	my ($self) = @_;

	my $raised = $self->message;
	$raised =~ s/\s+\z//;

	my $caller = $self->caller;
	if (defined $caller) {
		$raised .= ' (raised at ' . $caller->[1] . ', line ' . $caller->[2] . ')';
	}

	my $class = ref $self;
	$class =~ s/Bitcoin::Crypto::Exception:://;

	return "An error occured in Bitcoin subroutines: [$class] $raised";
}

{

	package Bitcoin::Crypto::Exception::Transaction;

	use parent -norequire, 'Bitcoin::Crypto::Exception';

}

{

	package Bitcoin::Crypto::Exception::UTXO;

	use parent -norequire, 'Bitcoin::Crypto::Exception';

}

{

	package Bitcoin::Crypto::Exception::Sign;

	use parent -norequire, 'Bitcoin::Crypto::Exception';

}

{

	package Bitcoin::Crypto::Exception::Verify;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::KeyCreate;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::KeyDerive;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::MnemonicGenerate;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::MnemonicCheck;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::Base58InputFormat;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::Base58InputChecksum;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::Bech32InputFormat;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::Bech32InputData;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::Bech32InputChecksum;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::SegwitProgram;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::ScriptType;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::ScriptOpcode;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::ScriptPush;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::ScriptSyntax;

	use Moo;
	use Mooish::AttributeBuilder -standard;
	use Bitcoin::Crypto::Types qw(PositiveOrZeroInt ArrayRef);

	extends 'Bitcoin::Crypto::Exception';

	has field 'script' => (
		isa => ArrayRef,
		writer => 1,
		predicate => 1,
	);

	has field 'error_position' => (
		isa => PositiveOrZeroInt,
		writer => 1,
		predicate => 1,
	);

	sub as_string
	{
		my ($self) = @_;
		my $message = $self->SUPER::as_string;

		if ($self->has_script && $self->has_error_position) {
			my @script = @{$self->script};
			$script[$self->error_position] = '> ' . $script[$self->error_position] . ' <-- here';
			$message .= "\n" . join ' ', @script;
		}

		return $message;
	}
}

{

	package Bitcoin::Crypto::Exception::ScriptRuntime;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::TransactionScript;

	use parent -norequire,
		'Bitcoin::Crypto::Exception::Transaction',
		'Bitcoin::Crypto::Exception::ScriptRuntime';
}

{

	package Bitcoin::Crypto::Exception::NetworkCheck;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::NetworkConfig;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::AddressGenerate;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Exception - Internal exception classes for Bitcoin::Crypto

=head1 SYNOPSIS

	try {
		decode_segwit('Not a segwit address');
	}
	catch ($error) {
		# $error is an instance of Bitcoin::Crypto::Exception and stringifies automatically
		warn "$error";

		# it also contains some information about the problem to avoid regex matching
		if ($error->isa('Bitcoin::Crypto::Exception::Bech32InputFormat')) {
			log $error->message;
		}
	}

=head1 DESCRIPTION

An exception wrapper class with automatic stringification and standarized
raising.

Contains inline packages that identify parts that went wrong (like
C<Bitcoin::Crypto::Exception::Sign> for errors in signature generation). Search
individual Bitcoin::Crypto packages documentation for a list the exception
classes to check for extra control flow when needed.

=head1 INTERFACE

=head2 Attributes

=head3 message

The wrapped error message (a string). Note: this is the raw message,
not the serialized form like in L</as_string>.

=head3 caller

B<Not assignable in the constructor>

An array ref containing: package name, file name and line number (same
as C<[caller()]> perl expression). It will point to the first place from
outside Bitcoin::Crypto which called it. May be undefined if it cannot find a
calling source.

=head2 Methods

=head3 new

	$runner = Bitcoin::Crypto::Exception->new(%data)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>. For exceptions, it's probably
better to use L</raise> instead.

Returns class instance.

=head3 as_string

	$error_info = $object->as_string()

Stringifies the error, using the L</message> method, L</caller> method and some
extra text for context.

=head3 raise

	$object->raise()
	$class->raise($message)

Creates a new instance and throws it. If used on an object, throws it right away.

	try {
		# throws, but will be catched
		Bitcoin::Crypto::Exception->raise('something went wrong');
	}
	catch ($exception) {
		# throws again
		$exception->raise;
	}

=head3 throw

An alias to C<raise>.

=head3 trap_into

	$sub_result = $class->trap_into($sub, $prefix)

Executes the given subroutine in an exception-trapping environment. Any
exceptions thrown inside the subroutine C<$sub> will be re-thrown after turning
them into objects of the given C<::Exception> class. If no exception is thrown,
method returns the value returned by C<$sub>.

	my $result = Bitcoin::Crypto::Exception->trap_into(sub {
		die 'something went wrong';
	});

C<$prefix> can be specified to better format the message.

