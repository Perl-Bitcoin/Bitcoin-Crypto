package Bitcoin::Crypto::Transaction::Signer::Role::KeyHash;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard, -role;
use Types::Common -sigs;

use Bitcoin::Crypto::Types -types;

requires qw(
	add_signature
	add_bytes
);

signature_for _add_pkh => (
	method => Object,
	head => [InstanceOf ['Bitcoin::Crypto::Key::Private']],
	named => [
		sighash => Maybe [PositiveOrZeroInt],
		{default => undef},
	],
	bless => !!0,
);

sub _add_pkh
{
	my ($self, $privkey, $args) = @_;

	$self->add_bytes($privkey->get_public_key->to_serialized);
}

before 'add_signature' => sub {
	my $self = shift;
	$self->_add_pkh(@_);
};

1;

