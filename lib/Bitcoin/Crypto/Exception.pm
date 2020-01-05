package Bitcoin::Crypto::Exception;

use Modern::Perl "2010";
use Moo;
use MooX::Types::MooseLike::Base qw(Str Bool);
use Carp;
use Scalar::Util qw(blessed);

use overload q("") => \&stringify;

has "is_exception" => (
	is => "ro",
	isa => Bool,
	default => 1,
);

has "code" => (
	is => "ro",
	isa => Str,
	required => 1,
);

has "message" => (
	is => "ro",
	isa => Str,
	required => 1,
);

sub stringify
{
	my ($self) = @_;
	return  $self->message . "(" . $self->code . ")";
}

sub raise
{
	my ($subj, %args) = @_;
	my $obj = blessed($subj) ? $subj : $subj->new(%args);

	croak $obj;
}

sub warn
{
	my ($subj, %args) = @_;
	$args{is_exception} = 0;
	my $obj = blessed($subj) ? $subj : $subj->new(%args);

	carp $obj;
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
		if ($error->code eq "bech32_input_format") {
			log $error->message;
		}
	};

=head1 DESCRIPTION

A wrapper class with automatic stringification and standarized raising.
Has two properties - B<code>, which is a machine readable hint about what went wrong and B<message>, which is a human readable description of an error. If you make your warnings into exceptions, you might find B<is_exception> useful, which holds the information about the original type of error.
Uses croak for errors and carp for warnings.

=head1 FUNCTIONS

=head2 raise

	Bitcoin::Crypto::Exception->raise(code => "fatal", message => "error");

Creates a new instance and croaks it. If used on an object, croaks it right away.

=head2 warn

	Bitcoin::Crypto::Exception->warn(code => "fatal", message => "error");

Creates a new instance and carps it. If used on an object, carps it right away.

=cut
