package Bitcoin::Crypto::Transaction::Signer;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;
use Carp qw(croak);

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Util qw(to_format);

use namespace::clean;

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
);

has param 'signing_index' => (
	isa => PositiveOrZeroInt,
);

has param 'script' => (
	coerce => BitcoinScript,
);

has field '_signature' => (
	isa => ArrayRef,
	default => sub { [] },
);

has field '_runner' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Runner'],
	lazy => 1,
);

sub _build_runner
{
	my ($self) = @_;

	my $runner = Bitcoin::Crypto::Script::Runner->new(
		transaction => $self->transaction
	);

	$runner->transaction->set_input_index($self->signing_index);
	$runner->start($self->script);
	return $runner;
}

sub _find_next_sigop
{
	my ($self, $error) = @_;
	$error //= !!1;

	my $runner = $self->_runner;
	my $ops = $runner->operations;
	while ('finding sigop') {
		my $pos = $runner->pos;

		if ($pos > $#$ops) {
			Bitcoin::Crypto::Exception::Sign->raise(
				'could not find a sigop'
			) if $error;

			last;
		}

		last if $ops->[$pos][0]->sigop;
		$runner->step;
	}

	return $runner;
}

sub _get_signature
{
	die 'unimplemented';
}

sub _initialize
{
	die 'unimplemented';
}

sub _finalize
{
	die 'unimplemented';
}

sub BUILD
{
	my ($self) = @_;

	$self->_initialize;
}

sub DEMOLISH
{
	my ($self, $global_des) = @_;

	return if $global_des;
	$self->finalize;
}

signature_for add_bytes => (
	method => Object,
	positional => [ByteStr],
);

sub add_bytes
{
	my ($self, $bytes) = @_;

	unshift @{$self->_runner->stack}, $bytes;
	push @{$self->_signature}, $bytes;

	return $self;
}

signature_for add_number => (
	method => Object,
	positional => [Int | Str | InstanceOf ['Math::BigInt']],
);

sub add_number
{
	my ($self, $number) = @_;

	return $self->add_bytes(Bitcoin::Crypto::Script::Runner->from_int($number));
}

signature_for add_signature => (
	method => Object,
	head => [ByteStr | InstanceOf ['Bitcoin::Crypto::Key::Private']],
	named => [
		sighash => Optional [PositiveOrZeroInt],
	],
	bless => !!0,
);

sub add_signature
{
	my ($self, $privkey_or_signature, $args) = @_;
	my $signature;
	my $runner = $self->_find_next_sigop;

	if (!ref $privkey_or_signature) {
		$signature = $privkey_or_signature;
	}
	else {
		$signature = $self->_get_signature($privkey_or_signature, $args);
	}

	$self->add_bytes($signature);
	$runner->step;

	return $self;
}

signature_for add_multisignature => (
	method => Object,
	positional => [
		ArrayRef [
			Tuple [
				ByteStr | InstanceOf ['Bitcoin::Crypto::Key::Private'],
				Slurpy [
					Dict [
						sighash => Optional [PositiveOrZeroInt],
					]
				],
			]
		],
		{slurpy => !!1}
	],
);

sub add_multisignature
{
	my ($self, $keys) = @_;
	my $runner = $self->_find_next_sigop;

	# reverse the key order, so they can be passed in the order of occurence in
	# the script
	foreach my $key (reverse @$keys) {
		my ($privkey_or_signature, %args) = @$key;
		my $signature;

		if (!ref $privkey_or_signature) {
			$signature = $privkey_or_signature;
		}
		else {
			$signature = $self->_get_signature($privkey_or_signature, \%args);
		}

		$self->add_bytes($signature);
	}

	# add mandatory nulldummy element
	$self->add_bytes('');

	$runner->step;
	return $self;
}

signature_for finalize => (
	method => Object,
	positional => [],
);

sub finalize
{
	my ($self) = @_;

	my $runner = $self->_runner;
	1 while $runner->step;

	Bitcoin::Crypto::Exception::Sign->raise(
		'bad signature - script yielded failure'
	) unless $runner->success;

	$self->_finalize;

	# no $self returned anymore - this object is done
	return;
}

signature_for dump => (
	method => Object,
	positional => [Bool, {default => !!1}],
);

sub dump
{
	my ($self, $find_sigop) = @_;

	my $runner = $self->_runner;
	$self->_find_next_sigop(!!0)
		if $find_sigop;

	my $pos = $runner->pos;
	my $ops = $runner->operations;

	my @result;
	push @result, "at position $pos (marked by **)";

	my @ops_dump;
	for my $this_pos ($pos - 2 .. $pos + 2) {
		my $op = $ops->[$this_pos];
		push @ops_dump, '**'
			if $this_pos == $pos;
		next unless $op;

		push @ops_dump, $op->[0]->name;
	}
	push @result, join ' ', @ops_dump;

	push @result, 'stack contents:';
	foreach my $item (@{$runner->stack}) {
		push @result, '> ' . to_format [hex => $item];
	}

	return join "\n", @result;
}

signature_for dump_abort => (
	method => Object,
	positional => [Bool, {default => !!1}],
);

sub dump_abort
{
	my ($self, $find_sigop) = @_;

	say $self->dump($find_sigop);
	croak 'signing aborted';
}

1;

