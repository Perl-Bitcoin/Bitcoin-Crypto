package Bitcoin::Crypto::Transaction;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Transaction::Input;
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Transaction::UTXO;
use Bitcoin::Crypto::Util qw(hash256);
use Bitcoin::Crypto::Helpers qw(pack_varint);
use Bitcoin::Crypto::Types
	qw(IntMaxBits ArrayRef InstanceOf HashRef Object Bool ByteStr PositiveInt PositiveOrZeroInt Enum BitcoinScript);

use constant SIGHASH_VALUES => {
	ALL => 0x01,
	NONE => 0x02,
	SINGLE => 0x03,
	ANYONECANPAY => 0x80,
};

has param 'version' => (
	isa => IntMaxBits [32],
	default => 1,
);

has param 'witness' => (
	isa => ArrayRef [ArrayRef [ByteStr]],
	default => sub { [] },
);

has field 'inputs' => (
	isa => ArrayRef [InstanceOf ['Bitcoin::Crypto::Transaction::Input']],
	default => sub { [] },
);

has field 'outputs' => (
	isa => ArrayRef [InstanceOf ['Bitcoin::Crypto::Transaction::Output']],
	default => sub { [] },
);

has param 'locktime' => (
	isa => IntMaxBits [32],
	default => 0,
);

signature_for add_witness => (
	method => Object,
	positional => [ArrayRef [ByteStr], {slurpy => 1}],
);

sub add_witness
{
	my ($self, $witness) = @_;

	push @{$self->witness}, $witness;
	return $self;
}

signature_for add_input => (
	method => Object,
	positional => [HashRef, {slurpy => 1}],
);

sub add_input
{
	my ($self, $data) = @_;

	$data = Bitcoin::Crypto::Transaction::Input->new($data)
		unless blessed $data && $data->isa('Bitcoin::Crypto::Transaction::Input');

	push @{$self->inputs}, $data;
	return $self;
}

signature_for add_output => (
	method => Object,
	positional => [HashRef, {slurpy => 1}],
);

sub add_output
{
	my ($self, $data) = @_;

	$data = Bitcoin::Crypto::Transaction::Output->new($data)
		unless blessed $data && $data->isa('Bitcoin::Crypto::Transaction::Output');

	push @{$self->outputs}, $data;
	return $self;
}

signature_for to_serialized => (
	method => Object,
	named => [
		_signing_index => PositiveOrZeroInt,
		{optional => 1},
		_signing_subscript => ByteStr,
		{optional => 1},
	],
);

sub to_serialized
{
	my ($self, $args) = @_;
	my $sign_no = $args->_signing_index;

	# transaction should be serialized as follows:
	# - version, 4 bytes
	# - number of inputs, 1-9 bytes
	# - serialized inputs
	# - number of outputs, 1-9 bytes
	# - serialized outputs
	# - lock time, 4 bytes
	my $serialized = '';

	$serialized .= pack 'V', $self->version;

	# Process inputs
	my @inputs = @{$self->inputs};
	Bitcoin::Crypto::Exception::Transaction->raise(
		'transaction has no inputs'
	) if @inputs == 0;

	Bitcoin::Crypto::Exception::Transaction->raise(
		"can't find input with index $sign_no"
	) if defined $sign_no && !$inputs[$sign_no];

	my $serialize_args = {};
	my @input_args = map { +{input => $_, args => $serialize_args} } @inputs;

	if (defined $sign_no) {

		# replace args reference of the input which we are signing
		$input_args[$sign_no]{args} = {
			signing => !!1,
			defined $args->_signing_subscript ? (signing_subscript => $args->_signing_subscript) : (),
		};

		# this will change args of every other input (via reference)
		$serialize_args->{signing} = !!0;
	}

	$serialized .= pack_varint(scalar @inputs);
	foreach my $input (@input_args) {

		# TODO: signature script should be empty if there's witness data?
		$serialized .= $input->{input}->to_serialized(%{$input->{args}});
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

signature_for to_serialized_witness => (
	method => Object,
	positional => [],
);

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
	# TODO: coinbase transaction may have no inputs!

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

signature_for get_hash => (
	method => Object,
	positional => [],
);

sub get_hash
{
	my ($self) = @_;

	return scalar reverse hash256($self->to_serialized);
}

signature_for get_digest => (
	method => Object,
	named => [
		signing_index => PositiveOrZeroInt,
		signing_subscript => ByteStr,
		{optional => 1},
		sighash => PositiveInt,
		{default => SIGHASH_VALUES->{ALL}}
	],
);

sub get_digest
{
	my ($self, $args) = @_;

	my $serialized = $self->to_serialized(
		_signing_index => $args->signing_index,
		defined $args->signing_subscript ? (_signing_subscript => $args->signing_subscript) : (),
	);

	my $procedure = $args->sighash & 31;
	my $anyonecanpay = $args->sighash & SIGHASH_VALUES->{ANYONECANPAY};

	if ($procedure == SIGHASH_VALUES->{NONE}) {

		# TODO
	}
	elsif ($procedure == SIGHASH_VALUES->{SINGLE}) {

		# TODO
	}

	$serialized .= pack 'V', $args->sighash;

	# TODO: sighash can be both ANYONECANPAY and other value at the same time
	# TODO: handle sighashes other than ALL

	return $serialized;
}

signature_for fee => (
	method => Object,
	positional => [],
);

sub fee
{
	my ($self) = @_;

	my $input_value = 0;
	foreach my $input (@{$self->inputs}) {
		$input_value += $input->utxo->output->value;
	}

	my $output_value = 0;
	foreach my $output (@{$self->outputs}) {
		$output_value += $output->value;
	}

	return $input_value - $output_value;
}

signature_for fee_rate => (
	method => Object,
	positional => [],
);

sub fee_rate
{
	my ($self) = @_;

	my $fee = $self->fee;
	my $size = $self->virtual_size;

	# TODO: BigInt does not play nice here (division)
	return "$fee" / $size;
}

signature_for virtual_size => (
	method => Object,
	positional => [],
);

sub virtual_size
{
	my ($self) = @_;

	my $base = length $self->to_serialized;
	my $with_witness = length $self->to_serialized_witness;
	my $witness = $with_witness - $base;

	return $base + $witness / 4;
}

signature_for weight => (
	method => Object,
	positional => [],
);

sub weight
{
	my ($self) = @_;

	my $base = length $self->to_serialized;
	my $with_witness = length $self->to_serialized_witness;
	my $witness = $with_witness - $base;

	return $base * 4 + $witness;
}

signature_for update_utxos => (
	method => Object,
	positional => [],
);

sub update_utxos
{
	my ($self) = @_;

	foreach my $input (@{$self->inputs}) {
		$input->utxo->unregister;
	}

	foreach my $output_index (0 .. $#{$self->outputs}) {
		my $output = $self->outputs->[$output_index];

		Bitcoin::Crypto::Transaction::UTXO->new(
			txid => $self->get_hash,
			output_index => $output_index,
			output => $output,
		)->register;
	}

	return $self;
}

signature_for verify_inputs => (
	method => Object,
	positional => [],
);

sub verify_inputs
{
	my ($self) = @_;

	my $script_runner = Bitcoin::Crypto::Script::Runner->new(
		transaction => $self,
	);

	my $input_index = 0;
	foreach my $input (@{$self->inputs}) {
		$script_runner->transaction->set_input_index($input_index);

		Bitcoin::Crypto::Exception::ScriptInvalid->trap_into(
			sub {
				# execute input to get initial stack
				$script_runner->execute($input->signature_script);
				my $stack = $script_runner->stack;

				# execute previous output
				$script_runner->execute($input->utxo->output->locking_script, $stack);
				my $stack_top = $script_runner->stack->[-1];

				die 'script yielded failure'
					unless $stack_top && $script_runner->to_bool($stack_top);
			},
			"transaction input $input_index verification has failed"
		);

		$input_index += 1;
	}

	return;
}

1;

