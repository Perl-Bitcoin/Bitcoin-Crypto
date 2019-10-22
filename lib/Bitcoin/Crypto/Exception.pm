package Bitcoin::Crypto::Exception;

use Modern::Perl "2010";
use Moo;
use MooX::Types::MooseLike::Base qw(Str);
use Carp qw(croak cluck);

use overload q("") => \&stringify;

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
	my ($class, %args) = @_;
	croak $class->new(%args);
}

sub warn
{
	my ($class, %args) = @_;
	cluck $class->new(%args);
}

1;
