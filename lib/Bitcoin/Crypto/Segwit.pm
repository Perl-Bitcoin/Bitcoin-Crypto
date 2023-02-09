package Bitcoin::Crypto::Segwit;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);

use Bitcoin::Crypto::Helpers qw(carp_once);
use Bitcoin::Crypto::Util;

our @EXPORT_OK = qw(
	validate_program
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

our %validators = (
);

sub validate_program
{
	carp_once "Bitcoin::Crypto::Segwit::validate_program is deprecated. Use Bitcoin::Crypto::Util::validate_segwit instead.";
	goto \&Bitcoin::Crypto::Util::validate_segwit;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Segwit - Segregated Witness version validators (DEPRECATED)

=head1 SYNOPSIS

	use Bitcoin::Crypto::Segwit qw(validate_program);

	my $program_version = validate_program($segwit_program);

=head1 DESCRIPTION

B<This module is now deprecated and will be removed. Use validate_segwit from
Bitcoin::Crypto::Util instead>

This module provides tools required to validate a Segregated Witness program of
a given version. It can be used to see if a bytestring looks like a witness program.

Currently, special validators are defined for version C<0>, I<SegWit>
addresses. Version C<1>, I<Taproot> does not define a special validator unless
an output is spent.

If you look for a way to encode a new type of address, see
L<Bitcoin::Crypto::Bech32/encode_segwit>.

=head1 FUNCTIONS

=head2 validate_program

	$segwit_version = validate_program($program)

Performs a segwit program validation on C<$program>, which is expected to be a
byte string in which the first byte is a segwit version. Based on this version
a validator is invoked, present in C<%Bitcoin::Crypto::Segwit::validators>
module hash variable.

The function returns the detected segwit program version. Note that it does not
perform any more checks than ensuring the byte string is in correct format.

The current implementation is in line with validations for segwit versions C<0>
and C<1>. Future segwit version addresses will work just fine, but no special
validation will be performed until implemented.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * SegwitProgram - a validation of a segwit program has failed

=back

=head1 SEE ALSO

L<Bitcoin::Crypto::Bech32>

