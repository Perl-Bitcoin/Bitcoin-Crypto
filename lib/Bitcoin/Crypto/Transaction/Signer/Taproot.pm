package Bitcoin::Crypto::Transaction::Signer::Taproot;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

extends 'Bitcoin::Crypto::Transaction::Signer::Segwit';

sub _multisigop
{
	return !!0;
}

sub finalize_multisignature
{
	Bitcoin::Crypto::Exception::Sign->raise(
		'taproot transactions do not support multisignatures'
	);
}

1;

