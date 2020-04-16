package Bitcoin::Crypto::Exception;

use Modern::Perl "2010";
use Moo;
use Throwable::Error;

extends "Throwable::Error";

sub raise
{
	shift->throw(@_);
}

{ package Bitcoin::Crypto::Exception::KeySign; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::KeyCreate; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::KeyDerive; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::MnemonicGenerate; use parent "Bitcoin::Crypto::Exception"; }

{ package Bitcoin::Crypto::Exception::Base58InputFormat; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::Base58InputChecksum; use parent "Bitcoin::Crypto::Exception"; }

{ package Bitcoin::Crypto::Exception::Bech32InputFormat; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::Bech32InputData; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::Bech32InputChecksum; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::SegwitProgram; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::ValidationTest; use parent "Bitcoin::Crypto::Exception"; }

{ package Bitcoin::Crypto::Exception::ScriptOpcode; use parent "Bitcoin::Crypto::Exception"; }
{ package Bitcoin::Crypto::Exception::ScriptPush; use parent "Bitcoin::Crypto::Exception"; }

{ package Bitcoin::Crypto::Exception::NetworkConfig; use parent "Bitcoin::Crypto::Exception"; }

no Moo;
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

A wrapper class with automatic stringification and standarized raising using Throwable::Error.
Contains many other inline packages that identify parts that went wrong (like Bitcoin::Crypto::Exception::KeySign for errors in signature generation).
See individual Bitcoin::Crypto packages documentation to see the exception classes to check for extra control flow when needed.

=head1 FUNCTIONS

=head2 raise

	Bitcoin::Crypto::Exception->raise("error message");

Creates a new instance and throws it. If used on an object, throws it right away.

=head2 throw

Same as raise.

=cut
