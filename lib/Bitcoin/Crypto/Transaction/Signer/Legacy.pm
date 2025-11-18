package Bitcoin::Crypto::Transaction::Signer::Legacy;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

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

	# TODO: MULTISIG
	my $script_pubkey = $runner->stack->[-1];
	Bitcoin::Crypto::Exception::Sign->raise(
		'bad private key for public key encountered in script sigop at position ' . $runner->pos
	) unless $script_pubkey eq $pubkey->to_serialized;

	my $digest_obj = $self->transaction->get_digest_object(
		signing_index => $self->signing_index,
		signing_subscript => $runner->subscript,
		(defined $args->{sighash} ? (sighash => $args->{sighash}) : ()),
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

