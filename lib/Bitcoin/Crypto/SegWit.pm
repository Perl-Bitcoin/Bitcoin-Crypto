package Bitcoin::Crypto::SegWit;

use Modern::Perl "2010";

use Bitcoin::Crypto::Exception;

our %segwit_validators = (
	0 => sub {
		my ($program) = @_;

	},
);

1;
