package Bitcoin::Crypto::SegWit;

use Modern::Perl "2010";
use Carp qw(croak);

our %segwit_validators = (
	0 => sub {
		my ($program) = @_;

	},
);
