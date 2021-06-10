package Bitcoin::Crypto::Exception;

our $VERSION = "0.997";

use v5.10;
use warnings;
use Moo;
use Types::Standard qw(Maybe Str ArrayRef);

use namespace::clean;

use overload
	q{""} => "as_string",
	fallback => 1;

has 'message' => (
	is => 'ro',
	isa => Str,
	required => 1,
);

has 'caller' => (
	is => 'ro',
	isa => Maybe [ArrayRef],
	default => sub {
		for my $call_level (1 .. 10) {
			my ($package, $file, $line) = caller $call_level;
			if (defined $package && $package !~ /^Bitcoin::Crypto/) {
				return [$package, $file, $line];
			}
		}
		return undef;
	},
	init_arg => undef,
);

sub raise
{
	my ($self, $error) = @_;

	unless (ref $self) {
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
	my ($class, $sub) = @_;

	# make sure we use class name
	$class = ref $class
		if ref $class;

	my $ret;
	my $error = do {
		local $@;
		my $failure = not eval {
			$ret = $sub->();
			return 1;
		};

		$@ || $failure;
	};

	if ($error) {

		# make sure we stringify the error
		$class->throw("$error");
	}

	return $ret;
}

sub as_string
{
	my ($self) = @_;

	my $raised = $self->message;
	$raised =~ s/\s$//g;
	my $caller = $self->caller;
	if (defined $caller) {
		$raised .= ' (raised at ' . $caller->[1] . ', line ' . $caller->[2] . ')';
	}
	return 'An error occured in Bitcoin subroutines: ' . $raised;
}

{

	package Bitcoin::Crypto::Exception::Sign;
	use parent -norequire, "Bitcoin::Crypto::Exception";

}

{

	# old form - deprecated
	package Bitcoin::Crypto::Exception::KeySign;
	use parent -norequire, "Bitcoin::Crypto::Exception::Sign";
}

{

	package Bitcoin::Crypto::Exception::Verify;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::KeyCreate;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::KeyDerive;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::MnemonicGenerate;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::MnemonicCheck;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::Base58InputFormat;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::Base58InputChecksum;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::Bech32InputFormat;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::Bech32InputData;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::Bech32InputChecksum;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::SegwitProgram;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::ValidationTest;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::ScriptOpcode;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::ScriptPush;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

{

	package Bitcoin::Crypto::Exception::NetworkConfig;
	use parent -norequire, "Bitcoin::Crypto::Exception";
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Exception - Exception class for Bitcoin::Crypto purposes

=head1 SYNOPSIS

	use Try::Tiny;

	try {
		decode_segwit("Not a segwit address");
	} catch {
		my $error = $_;

		# $error is an instance of Bitcoin::Crypto::Exception and stringifies automatically
		warn "$error";

		# but also contains some information about the problem to avoid regex matching
		if ($error->isa("Bitcoin::Crypto::Exception::Bech32InputFormat")) {
			log $error->message;
		}
	};

=head1 DESCRIPTION

A wrapper class with automatic stringification and standarized raising.
Contains many other inline packages that identify parts that went wrong (like Bitcoin::Crypto::Exception::Sign for errors in signature generation).
See individual Bitcoin::Crypto packages documentation to see the exception classes to check for extra control flow when needed.

=head1 FUNCTIONS

=head2 message

	sig: message($self)

Returns the error message (a string).

=head2 caller

	sig: caller($self)

Returns an array ref containing: package name, file name and line number (same as C<[caller()]> perl expression). It will contain the data for the first code from outside Bitcoin::Crypto which called it. May be undefined if it cannot find a calling source.

=head2 as_string

	sig: as_string($self)

Stringifies the error, using the I<message>, I<caller> and some extra text for context.

=head2 raise

	sig: raise($self)
	     raise($class, $message)

Creates a new instance and throws it. If used on an object, throws it right away.

	use Try::Tiny;

	try {
		# throws, but will be catched
		Bitcoin::Crypto::Exception->raise("something went wrong");
	} catch {
		my $exception = $_;

		# throws again
		$exception->raise;
	};

=head2 throw

An alias to raise.

=head2 trap_into

	sig: trap_into($class, $sub)

Executes the subroutine given as the only parameter inside an eval. Any exceptions thrown inside the subroutine will be re-thrown after turning them into objects of the given class. If no exception is thrown, method returns the value returned by the subroutine.

	my $result = Bitcoin::Crypto::Exception->trap_into(sub {
		die "something went wrong";
	});

=cut
