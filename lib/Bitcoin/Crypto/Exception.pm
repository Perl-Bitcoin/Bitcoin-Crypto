package Bitcoin::Crypto::Exception;

use Modern::Perl "2010";
use Moo;
use MooX::Types::MooseLike::Base qw(Str);
use Carp qw(croak);

use overload q("") => \&stringify;

has "code" => (
	is => "ro",
	isa => Str,
);

has "message" => (
	is => "ro",
	isa => Str,
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

1;
