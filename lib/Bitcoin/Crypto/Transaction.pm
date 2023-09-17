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
use Bitcoin::Crypto::Transaction::Digest;
use Bitcoin::Crypto::Util qw(hash256 to_format);
use Bitcoin::Crypto::Helpers qw(pack_varint unpack_varint);
use Bitcoin::Crypto::Types
	qw(IntMaxBits ArrayRef InstanceOf HashRef Object ByteStr Str PositiveInt PositiveOrZeroInt Enum BitcoinScript Bool);
use Bitcoin::Crypto::Script::Common;

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

with qw(
	Bitcoin::Crypto::Role::ShallowClone
);

signature_for add_input => (
	method => Object,
	positional => [ArrayRef, {slurpy => 1}],
);

sub add_input
{
	my ($self, $data) = @_;

	if (@$data == 1) {
		$data = $data->[0];

		Bitcoin::Crypto::Exception::Transaction->raise(
			'expected an input object'
		) unless blessed $data && $data->isa('Bitcoin::Crypto::Transaction::Input');
	}
	else {
		$data = Bitcoin::Crypto::Transaction::Input->new(@$data);
	}

	push @{$self->inputs}, $data;
	return $self;
}

signature_for add_output => (
	method => Object,
	positional => [ArrayRef, {slurpy => 1}],
);

sub add_output
{
	my ($self, $data) = @_;

	if (@$data == 1) {
		$data = $data->[0];

		Bitcoin::Crypto::Exception::Transaction->raise(
			'expected an output object'
		) unless blessed $data && $data->isa('Bitcoin::Crypto::Transaction::Output');
	}
	else {
		$data = Bitcoin::Crypto::Transaction::Output->new(@$data);
	}

	push @{$self->outputs}, $data;
	return $self;
}

signature_for to_serialized => (
	method => Object,
	named => [
		witness => Bool,
		{default => 1},
	],
);

sub to_serialized
{
	my ($self, $args) = @_;

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

	my $with_witness = $args->witness && grep { $_->has_witness } @inputs;
	if ($with_witness) {
		$serialized .= "\x00\x01";
	}

	$serialized .= pack_varint(scalar @inputs);
	foreach my $input (@inputs) {
		$serialized .= $input->to_serialized;
	}

	# Process outputs
	my @outputs = @{$self->outputs};
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

signature_for from_serialized => (
	method => Str,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $serialized) = @_;
	my $pos = 0;

	my $version = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	my $witness_flag = (substr $serialized, $pos, 2) eq "\x00\x01";
	$pos += 2 if $witness_flag;

	my ($input_count_len, $input_count) = unpack_varint(substr $serialized, $pos, 9);
	$pos += $input_count_len;

	my @inputs;
	for (1 .. $input_count) {
		push @inputs, Bitcoin::Crypto::Transaction::Input->from_serialized(
			$serialized, pos => \$pos
		);
	}

	my ($output_count_len, $output_count) = unpack_varint(substr $serialized, $pos, 9);
	$pos += $output_count_len;

	my @outputs;
	for (1 .. $output_count) {
		push @outputs, Bitcoin::Crypto::Transaction::Output->from_serialized(
			$serialized, pos => \$pos
		);
	}

	if ($witness_flag) {
		foreach my $input (@inputs) {
			my ($input_witness_len, $input_witness) = unpack_varint(substr $serialized, $pos, 9);
			$pos += $input_witness_len;

			my @witness;
			for (1 .. $input_witness) {
				my ($witness_count_len, $witness_count) = unpack_varint(substr $serialized, $pos, 9);
				$pos += $witness_count_len;

				push @witness, substr $serialized, $pos, $witness_count;
				$pos += $witness_count;
			}

			$input->set_witness(\@witness);
		}
	}

	my $locktime = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized transaction data is corrupted'
	) if $pos != length $serialized;

	my $tx = $class->new(
		version => $version,
		locktime => $locktime,
	);

	@{$tx->inputs} = @inputs;
	@{$tx->outputs} = @outputs;

	return $tx;
}

signature_for get_hash => (
	method => Object,
	positional => [],
);

sub get_hash
{
	my ($self) = @_;

	return scalar reverse hash256($self->to_serialized(witness => 0));
}

signature_for get_digest => (
	method => Object,
	positional => [HashRef, {slurpy => !!1}],
);

sub get_digest
{
	my ($self, $params) = @_;

	$params->{transaction} = $self;
	my $digest = Bitcoin::Crypto::Transaction::Digest->new($params);
	return $digest->get_digest;
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

	my $base = length $self->to_serialized(witness => 0);
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

	my $base = length $self->to_serialized(witness => 0);
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

sub _verify_script_default
{
	my ($self, $input, $script_runner) = @_;
	my $locking_script = $input->utxo->output->locking_script;

	# execute input to get initial stack
	$script_runner->execute($input->signature_script);
	my $stack = $script_runner->stack;

	# execute previous output
	# NOTE: shallow copy of the stack
	Bitcoin::Crypto::Exception::TransactionScript->trap_into(
		sub {
			$script_runner->execute($locking_script, [@$stack]);
			die 'execution yielded failure'
				unless $script_runner->success;
		},
		'locking script'
	);

	if ($locking_script->has_type && $locking_script->type eq 'P2SH') {
		my $redeem_script = btc_script->from_serialized(pop @$stack);

		Bitcoin::Crypto::Exception::TransactionScript->trap_into(
			sub {
				$script_runner->execute($redeem_script, $stack);
				die 'execution yielded failure'
					unless $script_runner->success;
			},
			'redeem script'
		);

		if ($redeem_script->is_native_segwit) {
			$self->_verify_script_segwit($input, $script_runner, $redeem_script);
		}
	}
}

sub _verify_script_segwit
{
	my ($self, $input, $script_runner, $compat_script) = @_;

	die 'signature script is not empty in segwit input'
		unless $compat_script || $input->signature_script->is_empty;

	# execute input to get initial stack
	my $signature_script = btc_script->new;
	foreach my $witness (@{$input->witness}) {
		$signature_script->push($witness);
	}
	$script_runner->execute($signature_script);
	my $stack = $script_runner->stack;

	my $locking_script = $compat_script // $input->utxo->output->locking_script;
	my $hash = substr $locking_script->to_serialized, 2;
	my $actual_locking_script;
	if ($locking_script->type eq 'P2WPKH') {
		$actual_locking_script = Bitcoin::Crypto::Script::Common->new(PKH => $hash);
	}
	elsif ($locking_script->type eq 'P2WSH') {
		$actual_locking_script = Bitcoin::Crypto::Script::Common->new(WSH => $hash);
	}

	# execute previous output
	# NOTE: shallow copy of the stack
	Bitcoin::Crypto::Exception::TransactionScript->trap_into(
		sub {
			$script_runner->execute($actual_locking_script, [@$stack]);
			die 'execution yielded failure'
				unless $script_runner->success;
		},
		'segwit locking script'
	);

	if ($locking_script->type eq 'P2WSH') {
		my $redeem_script = btc_script->from_serialized(pop @$stack);

		Bitcoin::Crypto::Exception::TransactionScript->trap_into(
			sub {
				$script_runner->execute($redeem_script, $stack);
				die 'execution yielded failure'
					unless $script_runner->success;
			},
			'segwit redeem script'
		);
	}
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
		my $procedure = '_verify_script_default';
		$procedure = '_verify_script_segwit'
			if $utxo->output->locking_script->is_native_segwit;

		Bitcoin::Crypto::Exception::TransactionScript->trap_into(
			sub {
				$self->$procedure($input, $script_runner);
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

signature_for dump => (
	method => Object,
	named => [
	],
);

sub dump
{
	my ($self, $params) = @_;

	my @result;
	push @result, 'Transaction ' . to_format [hex => $self->get_hash];
	push @result, 'version: ' . $self->version;
	push @result, 'size: ' . $self->virtual_size . 'vB, ' . $self->weight . 'WU';
	push @result, 'fee: ' . $self->fee . ' sat (~' . int($self->fee_rate) . ' sat/vB)';
	push @result, 'locktime: ' . $self->locktime;
	push @result, '';

	push @result, @{$self->inputs} . ' inputs:';
	foreach my $input (@{$self->inputs}) {
		push @result, $input->dump;
		push @result, '';
	}

	push @result, @{$self->outputs} . ' outputs:';
	foreach my $output (@{$self->outputs}) {
		push @result, $output->dump;
		push @result, '';
	}

	return join "\n", @result;
}

1;

