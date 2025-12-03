package Bitcoin::Crypto::Transaction::Signer::Legacy;

use v5.14;
use warnings;

use Mooish::Base -standard;
use List::Util qw(any);

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

extends 'Bitcoin::Crypto::Transaction::Signer';

sub _initialize
{
	my ($self) = @_;

	# do nothing
}

sub _get_signature
{
	my ($self, $privkey, $args) = @_;
	my $runner = $self->_runner;
	my $pubkey = $privkey->get_public_key;

	if ($self->_multisigop) {
		my $stack = $runner->stack;
		my $pubkey_count = $runner->to_int($stack->[-1] // "\x00");
		my @pubkeys = @{$stack}[-1 - $pubkey_count .. -2];

		my $pubkey_serialized = $pubkey->to_serialized;
		Bitcoin::Crypto::Exception::Sign->raise(
			'bad private key for public keys encountered in script multisigop at position ' . $runner->pos
		) unless any { $_ eq $pubkey_serialized } @pubkeys;
	}
	else {
		my $script_pubkey = $runner->stack->[-1];
		Bitcoin::Crypto::Exception::Sign->raise(
			'bad private key for public key encountered in script sigop at position ' . $runner->pos
		) unless $script_pubkey eq $pubkey->to_serialized;
	}

	my $digest_obj = $runner->transaction->get_digest_object(
		sighash => $args->{sighash},
	);

	return $privkey->sign_message($digest_obj->get_digest)
		. pack 'C', $digest_obj->sighash;
}

sub _finalize
{
	my ($self) = @_;

	my $script = btc_script->new;
	foreach my $element (reverse @{$self->_signature}) {
		$script->push($element);
	}

	$self->transaction->inputs->[$self->signing_index]->set_signature_script($script);
}

1;

