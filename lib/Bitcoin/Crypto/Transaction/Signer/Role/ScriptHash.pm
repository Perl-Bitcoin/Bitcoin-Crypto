package Bitcoin::Crypto::Transaction::Signer::Role::ScriptHash;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;

requires qw(
	_initialize
	script
	_signature
);

after '_initialize' => sub {
	my ($self) = @_;

	# do not use add_bytes (not part of this script)
	push @{$self->_signature}, $self->script->to_serialized;
};

1;

