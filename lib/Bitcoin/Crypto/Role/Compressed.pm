package Bitcoin::Crypto::Role::Compressed;

use Modern::Perl "2010";
use Moo::Role;
use Types::Standard qw(Bool);

use Bitcoin::Crypto::Config;

has "compressed" => (
	is => "rw",
	isa => Bool,
	coerce => 1,
	default => $config{compress_public_point},
	writer => "_set_compressed"
);

sub set_compressed
{
	my ($self, $state) = @_;
	$state //= 1;
	$self->_set_compressed($state);
	return $self;
}

no Moo::Role;
1;
