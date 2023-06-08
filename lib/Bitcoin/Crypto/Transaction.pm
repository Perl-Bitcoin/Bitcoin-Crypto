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
use Bitcoin::Crypto::Types qw(IntMaxBits ArrayRef InstanceOf HashRef Object Bool ByteStr PositiveOrZeroInt Enum BitcoinScript);

use constant SIGHASH_VALUES => {
	ALL => 0x01,
	NONE => 0x02,
	SINGLE => 0x03,
	ANYONECANPAY => 0x80,
};

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

	$data = Bitcoin::Crypto::Transaction::Input->new($data)
		unless blessed $data && $data->isa('Bitcoin::Crypto::Transaction::Input');

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

	$data = Bitcoin::Crypto::Transaction::Output->new($data)
		unless blessed $data && $data->isa('Bitcoin::Crypto::Transaction::Output');

	push @{$self->outputs}, $data;
	return $self;
}

signature_for to_serialized => (
	method => Object,
	named => [sign_no => PositiveOrZeroInt, { optional => 1 }],
	named_to_list => 1,
);

sub to_serialized
{
	my ($self, $sign_no) = @_;

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

	# TODO: each input should have its own witness?

	$serialized .= pack_varint(scalar @inputs);
	foreach my $item_no (0 .. $#inputs) {
		my $item = $inputs[$item_no];
		# TODO: signature script should be empty if there's witness data?
		$serialized .= $item->to_serialized(defined $sign_no ? (for_signing => $sign_no == $item_no) : ());
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
	positional => [
		PositiveOrZeroInt,
		Enum[qw(ALL NONE SINGLE ANYONECANPAY)], { default => 'ALL' }
	],
);

sub get_digest
{
	my ($self, $input_number, $sighash) = @_;

	my $serialized = $self->to_serialized(sign_no => $input_number);
	$serialized .= pack 'V', SIGHASH_VALUES->{$sighash};

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

1;

