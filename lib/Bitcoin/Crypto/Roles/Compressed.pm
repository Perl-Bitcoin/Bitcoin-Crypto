package Bitcoin::Crypto::Roles::Compressed;

use Modern::Perl "2010";
use Moo::Role;
use MooX::Types::MooseLike::Base qw(Bool);

use Bitcoin::Crypto::Config;

has "compressed" => (
    is => "rw",
    isa => Bool,
    default => $config{compress_public_point},
    writer => "_setCompressed"
);

sub setCompressed
{
    my ($self, $state) = @_;
    $state //= 1;
    $self->_setCompressed($state);
    return $self;
}

1;
