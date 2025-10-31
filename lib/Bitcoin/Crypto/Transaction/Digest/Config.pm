package Bitcoin::Crypto::Transaction::Digest::Config;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types;

use Bitcoin::Crypto::Types -types;

has param 'signing_index' => (
	isa => PositiveOrZeroInt,
);

has param 'signing_subscript' => (
	coerce => ByteStr,
	required => 0,
);

has param 'sighash' => (
	isa => PositiveOrZeroInt,
	required => 0,
	writer => -hidden,
);

has param 'taproot_ext_flag' => (
	isa => PositiveOrZeroInt,
	default => 0,
);

has param 'taproot_ext' => (
	coerce => ByteStr,
	required => 0,
);

has param 'taproot_annex' => (
	coerce => ByteStr,
	required => 0,
);

sub _default_sighash
{
	my ($self, $value) = @_;

	if (!defined $self->sighash) {
		$self->_set_sighash($value);
	}
}

1;

