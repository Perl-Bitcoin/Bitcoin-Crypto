package Bitcoin::Crypto::Exception;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Feature::Compat::Try;
use Scalar::Util qw(blessed);

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
			my $package_ok = defined $package && $package !~ /^(Bitcoin::Crypto|Try::Tiny|Type::Coercion)/;
			my $file_ok = defined $file && $file !~ /\(eval \d+\)/;

			if ($package_ok && $file_ok) {
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
	# try to be fast here. Only unpack arguments if executing the sub fails
	try {
		return $_[1]->();
	}
	catch ($ex) {
		my ($class, $sub, $prefix) = @_;

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

		my $ex_string = "$ex";
		chomp $ex_string;    # remove \n from die_no_trace
		$class->raise($prefix ? "$prefix: $ex_string" : $ex_string);
	}
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

	package Bitcoin::Crypto::Exception::Base58;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::Base58InputFormat;

	use parent -norequire, 'Bitcoin::Crypto::Exception::Base58';
}

{

	package Bitcoin::Crypto::Exception::Base58InputChecksum;

	use parent -norequire, 'Bitcoin::Crypto::Exception::Base58';
}

{

	package Bitcoin::Crypto::Exception::Bech32;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::Bech32InputFormat;

	use parent -norequire, 'Bitcoin::Crypto::Exception::Bech32';
}

{

	package Bitcoin::Crypto::Exception::Bech32InputData;

	use parent -norequire, 'Bitcoin::Crypto::Exception::Bech32';
}

{

	package Bitcoin::Crypto::Exception::Bech32InputChecksum;

	use parent -norequire, 'Bitcoin::Crypto::Exception::Bech32';
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

	package Bitcoin::Crypto::Exception::Block;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::ScriptTree;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::ScriptCompilation;

	use Mooish::Base -standard;

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

	package Bitcoin::Crypto::Exception::Address;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

{

	package Bitcoin::Crypto::Exception::AddressGenerate;

	use parent -norequire, 'Bitcoin::Crypto::Exception::Address';
}

{

	package Bitcoin::Crypto::Exception::PSBT;

	use parent -norequire, 'Bitcoin::Crypto::Exception';
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Exception - Exception classes for Bitcoin::Crypto

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

An exception wrapper class with automatic stringification and standardized
raising.

Contains inline packages that identify parts that went wrong (like
C<Bitcoin::Crypto::Exception::Sign> for errors in signature generation). Search
individual Bitcoin::Crypto packages documentation for a list the exception
classes to check for extra control flow when needed.

=head1 EXCEPTION SUBCLASSES

This module defines the following subclasses to Bitcoin::Crypto::Exception:

=head2 Bitcoin::Crypto::Exception::Transaction

Thrown when a general problem with a transaction is detected, for example:
non-script verification failure, corrupted serialized transaction data.

=head2 Bitcoin::Crypto::Exception::UTXO

Thrown when a problem with UTXO is detected, most notably inability to find the UTXO.

=head2 Bitcoin::Crypto::Exception::Sign

Thrown when a problem occurs during signing a transaction or message.

=head2 Bitcoin::Crypto::Exception::KeyCreate

Thrown when a problem occurs during creation of a key.

=head2 Bitcoin::Crypto::Exception::KeyDerive

Thrown when a problem occurs during derivation of a key.

=head2 Bitcoin::Crypto::Exception::MnemonicCheck

Thrown when a mnemonic checking was unsuccessful.

=head2 Bitcoin::Crypto::Exception::Base58

Thrown when a general base58 format problem is detected.

=head2 Bitcoin::Crypto::Exception::Base58InputFormat

Thrown when input does not look like valid base58. Subclass of
L</Bitcoin::Crypto::Exception::Base58>.

=head2 Bitcoin::Crypto::Exception::Base58InputChecksum

Thrown when base58check input checksum is invalid. Subclass of
L</Bitcoin::Crypto::Exception::Base58>.

=head2 Bitcoin::Crypto::Exception::Bech32

Thrown when a general Bech32 format problem is detected.

=head2 Bitcoin::Crypto::Exception::Bech32InputFormat

Thrown when input does not look like valid bech32. Subclass of
L</Bitcoin::Crypto::Exception::Bech32>.

=head2 Bitcoin::Crypto::Exception::Bech32InputData

Thrown when input is valid bech32, but contains invalid data. Subclass of
L</Bitcoin::Crypto::Exception::Bech32>.

=head2 Bitcoin::Crypto::Exception::Bech32InputChecksum

Thrown when bech32 input checksum is invalid. Subclass of
L</Bitcoin::Crypto::Exception::Bech32>.

=head2 Bitcoin::Crypto::Exception::SegwitProgram

Thrown when an issue with Segregated Witness program is detected.

=head2 Bitcoin::Crypto::Exception::ScriptType

Thrown when an unexpected script type is encountered.

=head2 Bitcoin::Crypto::Exception::ScriptOpcode

Thrown when unexpected script operation is encountered.

=head2 Bitcoin::Crypto::Exception::ScriptPush

Thrown when bad script push operation is performed.

=head2 Bitcoin::Crypto::Exception::Block

Thrown when a general problem with a block is detected.

=head2 Bitcoin::Crypto::Exception::ScriptTree

Thrown when a general problem with a script tree is detected.

=head2 Bitcoin::Crypto::Exception::ScriptCompilation

Thrown when a script compilation fails. It can only be thrown just
before the script is executed.

=head2 Bitcoin::Crypto::Exception::ScriptRuntime

Thrown when an error occurs during script runtime.

=head2 Bitcoin::Crypto::Exception::TransactionScript

Thrown when an error occurs in execution of scripts during
transaction validation. Subclass of
L</Bitcoin::Crypto::Exception::Transaction> and
L</Bitcoin::Crypto::Exception::ScriptRuntime>.

=head2 Bitcoin::Crypto::Exception::NetworkCheck

Thrown when an assumption about network is not met. This can happen
in single-network mode or if a network parameter is used, but it
does not match the arguments.

=head2 Bitcoin::Crypto::Exception::NetworkConfig

Thrown when network configuration is bad or insufficient to perform
the operation.

=head2 Bitcoin::Crypto::Exception::Address

Thrown when a general error connected to addresses is encountered.

=head2 Bitcoin::Crypto::Exception::AddressGenerate

Thrown when an error is encountered while generating an address. Subclass of
L</Bitcoin::Crypto::Exception::Address>.

=head2 Bitcoin::Crypto::Exception::PSBT

Thrown when a problem with PSBT format was encountered.

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

