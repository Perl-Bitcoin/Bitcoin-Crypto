package Bitcoin::Crypto::Role::Network;

use Modern::Perl "2010";
use Moo::Role;
use MooX::Types::MooseLike::Base qw(HashRef);

use Bitcoin::Crypto::Network qw(get_default_network get_network validate_network);

has "network" => (
	is => "rw",
	isa => HashRef,
	default => sub {
		return get_default_network();
	},
	writer => "_setNetwork"
);

sub setNetwork
{
	my ($self, $network) = @_;
	if (ref $network eq ref {}) {
		validate_network($network);
	} else {
		$network = get_network($network);
	}
	$self->_setNetwork($network);
	return $self;
}

1;
