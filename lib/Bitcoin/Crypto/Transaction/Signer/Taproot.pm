package Bitcoin::Crypto::Transaction::Signer::Taproot;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

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

