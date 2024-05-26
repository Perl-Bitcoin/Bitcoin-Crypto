package Bitcoin::Crypto::Transaction;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use Scalar::Util qw(blessed);
use Carp qw(carp);
use List::Util qw(sum);

use Bitcoin::Crypto qw(btc_script btc_utxo);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Transaction::Input;
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Transaction::Digest;
use Bitcoin::Crypto::Util qw(pack_varint unpack_varint hash256 to_format);
use Bitcoin::Crypto::Types
	qw(IntMaxBits ArrayRef InstanceOf HashRef Object ByteStr Str PositiveInt PositiveOrZeroInt Enum BitcoinScript Bool Maybe);
use Bitcoin::Crypto::Script::Common;

use namespace::clean;

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
	positional => [ArrayRef, {slurpy => !!1}],
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
	positional => [ArrayRef, {slurpy => !!1}],
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
	bless => !!0,
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

	my $with_witness = $args->{witness} && grep { $_->has_witness } @inputs;
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

	my $input_count = unpack_varint $serialized, \$pos;
	my @inputs;
	for (1 .. $input_count) {
		push @inputs, Bitcoin::Crypto::Transaction::Input->from_serialized(
			$serialized, pos => \$pos
		);
	}

	my $output_count = unpack_varint $serialized, \$pos;
	my @outputs;
	for (1 .. $output_count) {
		push @outputs, Bitcoin::Crypto::Transaction::Output->from_serialized(
			$serialized, pos => \$pos
		);
	}

	if ($witness_flag) {
		foreach my $input (@inputs) {
			my $input_witness = unpack_varint $serialized, \$pos;
			my @witness;
			for (1 .. $input_witness) {
				my $witness_count = unpack_varint $serialized, \$pos;

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
		return undef unless $input->utxo_registered;
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
	return undef unless defined $fee;

	my $size = $self->virtual_size;
	return $fee->as_float / $size;
}

signature_for set_rbf => (
	method => Object,
	positional => [],
);

sub set_rbf
{
	my ($self) = @_;

	# rules according to BIP125
	# https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
	if (!$self->has_rbf) {
		$self->inputs->[0]->set_sequence_no(Bitcoin::Crypto::Constants::rbf_sequence_no_threshold);
	}

	return $self;
}

signature_for has_rbf => (
	method => Object,
	positional => [],
);

sub has_rbf
{
	my ($self) = @_;

	foreach my $input (@{$self->inputs}) {
		return !!1
			if $input->sequence_no <= Bitcoin::Crypto::Constants::rbf_sequence_no_threshold;
	}

	return !!0;
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
		$input->utxo->unregister if $input->utxo_registered;
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

	Bitcoin::Crypto::Exception::TransactionScript->raise(
		'signature script must only contain push opcodes'
	) unless $input->signature_script->is_pushes_only;

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
	foreach my $witness (@{$input->witness // []}) {
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
		block => Maybe [InstanceOf ['Bitcoin::Crypto::Block']],
		{default => undef},
	],
	bless => !!0,
);

sub verify
{
	my ($self, $args) = @_;
	my $block = $args->{block};

	my $script_runner = Bitcoin::Crypto::Script::Runner->new(
		transaction => $self,
	);

	my @inputs = @{$self->inputs};

	# amount checking
	my $total_in = sum map { $_->utxo->output->value } @inputs;
	my $total_out = sum map { $_->value } @{$self->outputs};

	Bitcoin::Crypto::Exception::Transaction->raise(
		'output value exceeds input'
	) if $total_in < $total_out;

	# locktime checking
	if (
		$self->locktime > 0 && grep {
			$_->sequence_no != Bitcoin::Crypto::Constants::max_sequence_no
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
	positional => [],
);

sub dump
{
	my ($self) = @_;

	my $fee = $self->fee;
	my $fee_rate = defined $fee ? int($self->fee_rate * 100) / 100 : '??';
	$fee //= '??';

	my @result;
	push @result, 'Transaction ' . to_format [hex => $self->get_hash];
	push @result, 'version: ' . $self->version;
	push @result, 'size: ' . $self->virtual_size . 'vB, ' . $self->weight . 'WU';
	push @result, "fee: $fee sat (~$fee_rate sat/vB)";
	push @result, 'replace-by-fee: ' . ($self->has_rbf ? 'yes' : 'no');
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

__END__
=head1 NAME

Bitcoin::Crypto::Transaction - Bitcoin transaction instance

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_utxo btc_transaction);

	# extract unspent transaction outputs from the previous transaction
	btc_utxo->extract([hex => $serialized_previous_tx]);

	# create transaction from its serialized form
	my $tx = btc_transaction->from_serialized([hex => $serialized_this_tx]);

	# this will verify the transaction and throw an exception if it is not correct
	$tx->verify;

	# dump the transaction in readable format
	print $tx->dump;

=head1 DESCRIPTION

Transaction support in Bitcoin::Crypto is provided on best-effort basis. The
goal is not to reimplement Bitcoin Core, which would most likely lead to security
issues, but rather to provide means to manipulate a set of well-known standard
transaction types. Widely used C<P2PKH>, C<P2SH>, their SegWit counterparts and
C<P2MS> are thoroughly tested and should be safe to use. B<Still, before
putting any real money on the line, make sure to check the serialized
transactions in other tools and review that its contents are correct. There is
absolutely no guarantee!>

See L<Bitcoin::Crypto::Manual::Transactions> for details and guidelines.

=head1 INTERFACE

=head2 Attributes

=head3 version

Integer containing version of the transaction. By default C<1>.

I<Available in the constructor>.

=head3 inputs

The array reference of transaction inputs (L<Bitcoin::Crypto::Transaction::Input>).

It's better to use L<add_input> instead of pushing directly to this array.

=head3 outputs

The array reference of transaction outputs (L<Bitcoin::Crypto::Transaction::Output>).

It's better to use L<add_output> instead of pushing directly to this array.

=head3 locktime

Integer containing locktime of the transaction. By default C<0>.

I<Available in the constructor>.

=head2 Methods

=head3 new

	$tx = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 add_input

	$object = $object->add_input($input_object)
	$object = $object->add_input(%args)

Adds a new input to the transaction.

If a single scalar is passed, it must be a constructed object of L<Bitcoin::Crypto::Transaction::Input>.

Otherwise expects a hash of arguments passed to L<Bitcoin::Crypto::Transaction::Input/new>.

Returns itself (for chaining).

=head3 add_output

	$object = $object->add_output($output_object)
	$object = $object->add_output(%args)

Same as L</add_input>, but adds an output (L<Bitcoin::Crypto::Transaction::Output>).

=head3 to_serialized

	$serialized = $object->to_serialized(%params)

Serializes a transaction into a bytestring.

C<%params> can be any of:

=over

=item * C<witness>

Boolean, default C<1>. If C<0> is passed, forces serialization without witness
data. Note that this is a no-op in non-segwit transactions.

=back

=head3 from_serialized

	$object = $class->from_serialized($data)

Deserializes the bytestring C<$data> into a transaction object.

Keep in mind deserialization requires a full set of UTXO to be registered. If
they are not, an exception will be raised with missing transaction id and
output index, which should help you fill in the blanks. See
L<Bitcoin::Crypto::Transaction::UTXO> for details.

=head3 get_hash

	$txid = $object->get_hash()

Returns the hash of the transaction, also used as its id. The return value is a
bytestring.

NOTE: this method returns the hash in big endian, which is not suitable for
serialized transactions. If you want to manually encode the hash into the
transaction, you should first C<scalar reverse> it.

=head3 get_digest

	$digest = $object->get_digest(%params)

This method produces the digest preimage of the transaction. It is a bytestring
against which the input signature is created (after hashing it with
C<hash256>).

C<%params> can be any of:

=over

=item * C<signing_index>

This non-negative integer is the index of the input being signed. Required.

=item * C<signing_subscript>

The subscript used in digesting. It is only required for C<P2SH>, C<P2WSH> and
custom scripts.

=item * C<sighash>

The sighash which should be used for the digest. By default C<SIGHASH_ALL>.

=back

=head3 fee

	$fee = $object->fee()

Returns the fee - the difference between sum of input values and the sum of
output values. The fee is always zero or positive integer, but can be undefined
if the UTXOs were not registered.

=head3 fee_rate

	$fee_rate = $object->fee_rate()

Returns the fee rate - the amount of satoshi per virtual byte (a floating point
value) or undef if C<fee> is undef.

NOTE: since weight of the transaction changes after signing it, it is not
possible to accurately measure fee rate prior to signing.

=head3 set_rbf

	$object = $object->set_rbf()

Sets replace-by-fee for the transaction according to BIP125. The modification
of sequence number is always done on the first input. Has no effect if the
transaction already has the RBF rule.

=head3 has_rbf

	$bool = $object->has_rbf()

Returns true if the transaction is subject to replace-by-fee.

=head3 virtual_size

	my $vB_size = $object->virtual_size()

Returns the virtual size of the transaction (in vBytes).

C<virtual_size> is used for fee calculations. Normal transaction data is
calculated as 1 vByte per byte and witness data is calculated as 0.25 vByte per
byte.

=head3 weight

	my $WU_size = $object->weight()

Returns the weight of the transaction (in weight units).

Similar to L</virtual_size>, but normal transaction data is calculated as 4 WU
per byte and witness data is calculated as 1 WU per byte.

=head3 update_utxos

	$object = $object->update_utxos()

This method accepts the transaction as confirmed by the network. It unregisters
all UTXOs it consumed and registers its own outputs as new UTXOs. This means
new transactions can be created without the need to register the new UTXOs
manually.

NOTE: it does not verify the transaction by itself.

=head3 verify

	$object->verify(%params)

Verifies the transaction according to the Bitcoin consensus rules. Returns
nothing, but will throw an exception if the verification failed.

See L<Bitcoin::Crypto::Manual::Transactions/Current known problems with transactions>.

C<%params> can be any of:

=over

=item * C<block>

Optional instance of L<Bitcoin::Crypto::Block> - used for locktime and sequence
verification. If it is not passed and the transaction includes these checks, it
will still verify without an exception but a warning will be issued.

=back

=head3 dump

	$text = $object->dump()

Returns a readable description of the transaction.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * Transaction - general error with transaction

=item * TransactionScript - error during transaction scripts execution

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction::Input>

=item L<Bitcoin::Crypto::Transaction::Output>

=item L<Bitcoin::Crypto::Transaction::UTXO>

=item L<Bitcoin::Crypto::Script>

=back

=cut

