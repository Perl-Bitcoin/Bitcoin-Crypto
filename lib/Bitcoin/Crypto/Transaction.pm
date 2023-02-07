package Bitcoin::Crypto::Transaction;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Transaction::Input;
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Util qw(hash256);
use Bitcoin::Crypto::Helpers qw(pack_varint);
use Bitcoin::Crypto::Types qw(IntMaxBits ArrayRef InstanceOf HashRef Object Bool ByteStr);

has param 'version' => (
	isa => IntMaxBits[32],
	default => 1,
);

has param 'witness' => (
	isa => ArrayRef[ArrayRef[ByteStr]],
	default => sub { [] },
);

has field 'inputs' => (
	isa => ArrayRef[InstanceOf['Bitcoin::Crypto::Transaction::Input']],
	default => sub { [] },
);

has field 'outputs' => (
	isa => ArrayRef[InstanceOf['Bitcoin::Crypto::Transaction::Output']],
	default => sub { [] },
);

has param 'locktime' => (
	isa => IntMaxBits[32],
	default => 0,
);

signature_for add_witness => (
	method => Object,
	positional => [ArrayRef[ByteStr], { slurpy => 1 }],
);

sub add_witness
{
	my ($self, $witness) = @_;

	push @{$self->witness}, $witness;
	return $self;
}

signature_for add_input => (
	method => Object,
	positional => [HashRef, { slurpy => 1 }],
);

sub add_input
{
	my ($self, $data) = @_;

	$data = Bitcoin::Crypto::Transaction::Input->new($data);

	push @{$self->inputs}, $data;
	return $self;
}

signature_for add_output => (
	method => Object,
	positional => [HashRef, { slurpy => 1 }],
);

sub add_output
{
	my ($self, $data) = @_;

	$data = Bitcoin::Crypto::Transaction::Output->new($data);

	push @{$self->outputs}, $data;
	return $self;
}

sub to_serialized
{
	my ($self) = @_;

	# transaction should be serialized as follows:
	# - version, 4 bytes
	# - number of inputs, 1-9 bytes
	# - serialized inputs
	# - number of outputs, 1-9 bytes
	# - serialized outputs
	# - lock time, 4 bytes
	my $serialized = '';

	my @witness = @{$self->witness};

	$serialized .= pack 'V', $self->version;

	# Process inputs
	my @inputs = @{$self->inputs};
	Bitcoin::Crypto::Exception::Transaction->raise(
		'transaction has no inputs'
	) if @inputs == 0;

	# TODO: each input should have its own witness?

	$serialized .= pack_varint(scalar @inputs);
	foreach my $item (@inputs) {
		# TODO: signature script should be empty if there's witness data?
		$serialized .= $item->to_serialized;
	}

	# Process outputs
	my @outputs = @{$self->outputs};
	Bitcoin::Crypto::Exception::Transaction->raise(
		'transaction has no outputs'
	) if @outputs == 0;

	$serialized .= pack_varint(scalar @outputs);
	foreach my $item (@outputs) {
		$serialized .= $item->to_serialized;
	}

	$serialized .= pack 'V', $self->locktime;

	return $serialized;
}

sub to_serialized_witness
{
	my ($self) = @_;

	# transaction should be serialized as follows:
	# - version, 4 bytes
	# - 0x0001, if witness data is present
	# - number of inputs, 1-9 bytes
	# - serialized inputs
	# - number of outputs, 1-9 bytes
	# - serialized outputs
	# - witness data
	# - lock time, 4 bytes
	my $serialized = '';

	my @witness = @{$self->witness};

	$serialized .= pack 'V', $self->version;
	$serialized .= chr 0;
	$serialized .= chr 1;

	# Process inputs
	my @inputs = @{$self->inputs};
	Bitcoin::Crypto::Exception::Transaction->raise(
		'transaction has no inputs'
	) if @inputs == 0;

	# TODO: each input should have its own witness?

	$serialized .= pack_varint(scalar @inputs);
	foreach my $item (@inputs) {
		# TODO: signature script should be empty if there's witness data?
		$serialized .= $item->to_serialized;
	}

	# Process outputs
	my @outputs = @{$self->outputs};
	Bitcoin::Crypto::Exception::Transaction->raise(
		'transaction has no outputs'
	) if @outputs == 0;

	$serialized .= pack_varint(scalar @outputs);
	foreach my $item (@outputs) {
		$serialized .= $item->to_serialized;
	}

	foreach my $item (@witness) {
		my @this_witness = @{$item};

		$serialized .= pack_varint(scalar @this_witness);
		foreach my $witness_item (@this_witness) {
			$serialized .= pack_varint(length $witness_item);
			$serialized .= $witness_item;
		}
	}

	$serialized .= pack 'V', $self->locktime;

	return $serialized;
}

sub get_hash
{
	my ($self) = @_;

	return scalar reverse hash256($self->to_serialized);
}

sub fee
{
	my ($self) = @_;

	my $input_value = 0;
	foreach my $input (@{$self->inputs}) {
		Bitcoin::Crypto::Exception::Transaction->raise(
			'one of the inputs has no value - cannot calculate fee'
		) unless $input->has_value;

		$input_value += $input->value;
	}

	my $output_value = 0;
	foreach my $output (@{$self->outputs}) {
		$output_value += $output->value;
	}

	return $input_value - $output_value;
}

1;

