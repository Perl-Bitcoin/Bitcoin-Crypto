package Bitcoin::Crypto::Transaction;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use Scalar::Util qw(blessed);
use Carp qw(carp);

use Bitcoin::Crypto qw(btc_script btc_utxo);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Transaction::Input;
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Util qw(hash256);
use Bitcoin::Crypto::Helpers qw(pack_varint);
use Bitcoin::Crypto::Types
	qw(IntMaxBits ArrayRef InstanceOf HashRef Object ByteStr Str PositiveInt PositiveOrZeroInt Enum BitcoinScript Bool);

has param 'version' => (
	isa => IntMaxBits [32],
	default => 1,
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
		with_witness => Bool,
		{default => 1},
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

	# segwit transaction should be serialized as follows:
	# - version, 4 bytes
	# - 0x0001, if witness data is present
	# - number of inputs, 1-9 bytes
	# - serialized inputs
	# - number of outputs, 1-9 bytes
	# - serialized outputs
	# - witness data
	# - lock time, 4 bytes

	my $serialized = '';

	$serialized .= pack 'V', $self->version;

	# Process inputs
	my @inputs = @{$self->inputs};
	Bitcoin::Crypto::Exception::Transaction->raise(
		'transaction has no inputs'
	) if @inputs == 0;

	my $with_witness = $args->with_witness && grep { $_->has_witness } @inputs;
	if ($with_witness) {
		$serialized .= "\x00\x01";
	}

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

	if ($with_witness) {
		foreach my $input (@inputs) {
			my @this_witness = $input->has_witness ? @{$input->witness} : ();

			$serialized .= pack_varint(scalar @this_witness);
			foreach my $witness_item (@this_witness) {
				$serialized .= pack_varint(length $witness_item);
				$serialized .= $witness_item;
			}
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

	return scalar reverse hash256($self->to_serialized(with_witness => 0));
}

signature_for get_digest => (
	method => Object,
	named => [
		signing_index => PositiveOrZeroInt,
		signing_subscript => ByteStr,
		{optional => 1},
		sighash => PositiveInt,
		{default => Bitcoin::Crypto::Constants::sighash_all}
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
	my $anyonecanpay = $args->sighash & Bitcoin::Crypto::Constants::sighash_anyonecanpay;

	if ($procedure == Bitcoin::Crypto::Constants::sighash_none) {

		# TODO
	}
	elsif ($procedure == Bitcoin::Crypto::Constants::sighash_single) {

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

	return $fee->as_float / $size;
}

signature_for virtual_size => (
	method => Object,
	positional => [],
);

sub virtual_size
{
	my ($self) = @_;

	my $base = length $self->to_serialized(with_witness => 0);
	my $with_witness = length $self->to_serialized;
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

	my $base = length $self->to_serialized(with_witness => 0);
	my $with_witness = length $self->to_serialized;
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

		btc_utxo->new(
			txid => $self->get_hash,
			output_index => $output_index,
			output => $output,
		)->register;
	}

	return $self;
}

signature_for verify => (
	method => Object,
	named => [
		block => InstanceOf ['Bitcoin::Crypto::Block'],
		{optional => 1},
	],
);

sub verify
{
	my ($self, $args) = @_;
	my $block = $args->block;

	my $script_runner = Bitcoin::Crypto::Script::Runner->new(
		transaction => $self,
	);

	my @inputs = @{$self->inputs};

	# locktime checking
	if (
		$self->locktime > 0 && grep {
			$_->sequence_no != Bitcoin::Crypto::Constants::max_nsequence
		} @inputs
		)
	{
		if (defined $block) {
			my $locktime = $self->locktime;
			my $is_timestamp = $locktime >= Bitcoin::Crypto::Constants::locktime_height_threshold;

			Bitcoin::Crypto::Exception::Transaction->raise(
				'locktime was not satisfied'
			) if $locktime > ($is_timestamp ? $block->median_time_past : $block->height);
		}
		else {
			carp 'trying to verify locktime but no block parameter was passed';
		}
	}

	# per-input verification
	foreach my $input_index (0 .. $#inputs) {
		my $input = $inputs[$input_index];
		my $utxo = $input->utxo;
		$script_runner->transaction->set_input_index($input_index);

		# run bitcoin script
		Bitcoin::Crypto::Exception::TransactionScript->trap_into(
			sub {
				my $locking_script = $utxo->output->locking_script;

				# execute input to get initial stack
				$script_runner->execute($input->signature_script);
				my $stack = $script_runner->stack;

				# execute previous output
				# NOTE: shallow copy of the stack
				$script_runner->execute($locking_script, [@$stack]);

				die 'locking script execution yielded failure'
					unless $script_runner->success;

				# TODO: implement P2WSH
				if ($locking_script->has_type && grep { $_ eq $locking_script->type } qw(P2SH)) {
					my $redeem_script = btc_script->from_serialized(pop @$stack);

					$script_runner->execute($redeem_script, $stack);
					die 'redeem script execution yielded failure'
						unless $script_runner->success;
				}
			},
			"transaction input $input_index verification has failed"
		);

		# check sequence (BIP 68)
		if ($self->version >= 2 && !($input->sequence_no & (1 << 31))) {
			my $sequence = $input->sequence_no;
			my $time_based = $sequence & (1 << 22);
			my $relative_locktime = $sequence & 0x0000ffff;

			if (defined $block && $utxo->has_block) {
				my $utxo_block = $utxo->block;
				my $now = $time_based ? $block->median_time_past : $block->height;
				my $then = $time_based ? $utxo_block->median_time_past : $utxo_block->height;
				$relative_locktime <<= 9 if $time_based;

				Bitcoin::Crypto::Exception::Transaction->raise(
					'relative locktime was not satisfied'
				) if $now < $then + $relative_locktime;
			}
			else {
				carp 'trying to verify relative locktime but no block parameter was passed or utxo block was set';
			}
		}
	}

	return;
}

1;

