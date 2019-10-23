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
	return $self->code . ": " . $self->message;
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
