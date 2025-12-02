package Bitcoin::Crypto::Tapscript;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Tapscript::Opcode;

extends 'Bitcoin::Crypto::Script';

sub opcode_class
{
	return 'Bitcoin::Crypto::Tapscript::Opcode';
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Tapscript - Bitcoin script subclass for tapscripts

=head1 SYNOPSIS

	use Bitcoin::Crypto::Tapscript;

	# same usage as Bitcoin::Crypto::Script


=head1 DESCRIPTION

This is a L<Bitcoin::Crypto::Script> subclass used for dealing with tapscripts.
The main difference between scripts and tapscripts is a slightly different set
of opcodes.

=head1 METHODS

=head2 opcode_class

This method overrides the parent's version and returns
L<Bitcoin::Crypto::Tapscript::Opcode>.

