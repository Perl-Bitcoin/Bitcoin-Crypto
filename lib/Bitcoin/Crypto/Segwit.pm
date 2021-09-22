package Bitcoin::Crypto::Segwit;

our $VERSION = "1.001";

use v5.10;
use strict;
use warnings;
use Exporter qw(import);

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(verify_bytestring);

our @EXPORT_OK = qw(
	validate_program
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

our %validators = (
	0 => sub {
		my ($data) = @_;

		Bitcoin::Crypto::Exception::SegwitProgram->raise(
			"incorrect witness program length"
		) unless length $data == 20 || length $data == 32;
		return;
	},
);

sub common_validator
{
	my ($data) = @_;

	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		"incorrect witness program length"
	) unless length $data >= 2 && length $data <= 40;
	return;
}

sub validate_program
{
	my ($program) = @_;
	verify_bytestring($program);

	my $version = unpack "C", $program;
	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		"incorrect witness program version " . ($version // "[null]")
	) unless defined $version && $version >= 0 && $version <= Bitcoin::Crypto::Config::max_witness_version;

	$program = substr $program, 1;
	my $validator = $validators{$version};
	common_validator($program);
	if (defined $validator && ref $validator eq ref sub { }) {
		$validator->($program);
	}
	else {
		warn("No validator for SegWit program version $version is declared");
	}

	return $version;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Segwit - Segregated Witness version definitions

=head1 SYNOPSIS

	use Bitcoin::Crypto::Segwit qw(validate_program);

	my $program_version = validate_program($segwit_program);

=head1 DESCRIPTION

This module provides tools required to define and use a Segregated Witness version validator.

=head1 FUNCTIONS

=head2 validate_program

	$segwit_version = validate_program($program)

Performs a segwit program validation on $program, which is expected to be a byte string in which the first byte is a segwit version. Based on this version a validator is invoked, present in %Bitcoin::Crypto::Segwit::validators module hash. If the validator is not defined for a segwit version being validated, a warning is issued.

The function returns the detected segwit program version. Please note that it does not perform any more checks than ensuring the byte string is in correct format.

The current implementation defines a validator for segwit version 0. In the future (when another segwit program version is defined) it might be neccessary to define another one in the program until it's added to the library. This can be done like so:

	use Bitcoin::Crypto::Segwit;
	use Bitcoin::Crypto::Exception;

	$Bitcoin::Crypto::Segwit::validators{1} = sub {
		my ($data) = @_;

		# perform validation
		Bitcoin::Crypto::Exception::SegwitProgram->raise(
			"validation of program version 1 failed"
		) if ...;

		# if validation is successful just do nothing
		return;
	};


=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * SegwitProgram - a validation of a segwit program has failed

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Exception>

=item L<Bitcoin::Crypto::Bech32>

=back

=cut
