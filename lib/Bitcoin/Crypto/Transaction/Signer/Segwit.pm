package Bitcoin::Crypto::Transaction::Signer::Segwit;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

extends 'Bitcoin::Crypto::Transaction::Signer::Legacy';

sub _finalize
{
	my ($self) = @_;

	$self->transaction->inputs->[$self->signing_index]->set_witness(
		[reverse @{$self->signature}]
	);
}

1;

