package Bitcoin::Crypto::Block;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;
use Scalar::Util qw(blessed);
use Feature::Compat::Try;

use Bitcoin::Crypto qw(btc_transaction);
use Bitcoin::Crypto::Util::Internal qw(pack_compactsize unpack_compactsize hash256 to_format);
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

# Block header fields
has param 'version' => (
	isa => IntMaxBits [32],
	default => 1,
	writer => 1,
);

has option 'prev_block_hash' => (
	coerce => ByteStr,
	writer => 1,
);

has field 'merkle_root' => (
	isa => ByteStr,
	lazy => 1,
	clearer => 1,
);

has param 'timestamp' => (
	isa => PositiveInt,
	default => sub { scalar time },
	writer => 1,
);

has param 'bits' => (
	isa => IntMaxBits [32],
	default => 0x207fffff,    # Difficulty bits
	writer => 1,
);

has param 'nonce' => (
	isa => IntMaxBits [32],
	default => 0,
	writer => 1,
);

has param 'height' => (
	isa => Maybe [PositiveOrZeroInt],
	writer => 1,
	lazy => 1,
	required => 0,
	clearer => 1,
);

has option 'previous' => (
	isa => InstanceOf ['Bitcoin::Crypto::Block'],
	writer => 1,
	trigger => 1,
);

has field 'transactions' => (
	isa => ArrayRef [InstanceOf ['Bitcoin::Crypto::Transaction']],
	default => sub { [] },
);

sub has_transactions
{
	my ($self) = @_;

	return @{$self->transactions} > 0;
}

# need this written manually because height can be lazy-built conditionally
# (when block version is 2 or above and we have transactions, we can get it
# from coinbase)
sub has_height
{
	return defined $_[0]->height;
}

sub _build_height
{
	my ($self) = @_;

	return undef unless $self->has_transactions;

	my $tx = $self->transactions->[0];
	Bitcoin::Crypto::Exception::Block->raise(
		'first transaction is not coinbase'
	) unless $tx->is_coinbase;

	# TODO: check if height is minimally encoded?
	my $full_script = $tx->inputs->[0]->signature_script->to_serialized;
	my $size = unpack 'C', substr $full_script, 0, 1;
	Bitcoin::Crypto::Exception::Block->raise(
		'invalid height in coinbase transaction'
	) unless $size && ($size == 3 || $size == 5) && length $full_script > $size;

	try {
		my $result = Bitcoin::Crypto::Script::Runner
			->to_int(substr $full_script, 1, $size);

		# numify if bigint
		return "$result";
	}
	catch ($e) {
		return undef;
	}
}

sub add_transaction
{
	my ($self, @data) = @_;

	my $tx;
	if (@data == 1) {
		$tx = $data[0];

		Bitcoin::Crypto::Exception::Block->raise(
			'expected a transaction object'
		) unless blessed $tx && $tx->isa('Bitcoin::Crypto::Transaction');
	}
	else {
		$tx = btc_transaction->new(@data);
	}

	$tx->set_block($self);
	push @{$self->transactions}, $tx;

	# Clear cached merkle root if set
	$self->clear_merkle_root;

	return $self;
}

signature_for to_serialized => (
	method => !!1,
	named => [
		witness => Bool,
		{default => 1},
	],
	bless => !!0,
);

sub to_serialized
{
	my ($self, $args) = @_;

	# Bitcoin block serialization format:
	# - Block header (80 bytes):
	#   - version (4 bytes)
	#   - prev_block_hash (32 bytes)
	#   - merkle_root (32 bytes)
	#   - timestamp (4 bytes)
	#   - bits (4 bytes)
	#   - nonce (4 bytes)
	# - Transaction count (VarInt)
	# - Transactions (variable length)

	my $serialized = $self->get_header;

	# Transaction count
	$serialized .= pack_compactsize(scalar @{$self->transactions});

	# Transactions
	foreach my $tx (@{$self->transactions}) {
		$serialized .= $tx->to_serialized(witness => $args->{witness});
	}

	return $serialized;
}

signature_for from_serialized => (
	method => !!1,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $serialized) = @_;
	my $pos = 0;

	# optimization - no need to keep checking bytestrings on every level. It
	# has already been checked.
	local $Bitcoin::Crypto::Types::CHECK_BYTESTRINGS = !!0;

	Bitcoin::Crypto::Exception::Block->raise(
		'serialized block data too short for header'
	) if length($serialized) < 80;

	# Parse block header (80 bytes)
	my ($version, $prev_block_hash, $merkle_root, $timestamp, $bits, $nonce)
		= unpack 'Va32a32VVV', $serialized;
	$pos += 80;

	$prev_block_hash = reverse $prev_block_hash;
	$merkle_root = reverse $merkle_root;

	# Parse transaction count
	my $tx_count = unpack_compactsize $serialized, \$pos;

	my @transactions;

	# Parse transactions
	for my $tx_index (1 .. $tx_count) {
		push @transactions, btc_transaction->from_serialized(
			$serialized, pos => \$pos
		);
	}

	Bitcoin::Crypto::Exception::Block->raise(
		'serialized block data is corrupted'
	) if $pos != length $serialized;

	Bitcoin::Crypto::Exception::Block->raise(
		'block requires a coinbase transaction'
	) unless @transactions > 0 && $transactions[0]->is_coinbase;

	my $block = $class->new(
		version => $version,
		prev_block_hash => $prev_block_hash,
		timestamp => $timestamp,
		bits => $bits,
		nonce => $nonce,
	);

	@{$block->transactions} = @transactions;

	Bitcoin::Crypto::Exception::Block->raise(
		'serialized block merkle root is incorrect'
	) if $block->merkle_root ne $merkle_root;

	foreach my $tx (@transactions) {
		$tx->set_block($block);
	}

	return $block;
}

sub get_hash
{
	my ($self) = @_;
	return scalar reverse hash256($self->get_header);
}

sub get_header
{
	my ($self) = @_;

	# Return just the 80-byte block header
	return pack 'Va32a32VVV',
		$self->version,
		scalar(reverse $self->prev_block_hash),
		scalar(reverse $self->merkle_root),
		$self->timestamp,
		$self->bits,
		$self->nonce,
		;
}

sub _trigger_previous
{
	my ($self) = @_;

	return unless $self->previous->has_transactions;

	$self->set_prev_block_hash($self->previous->get_hash);
}

sub _build_merkle_root
{
	my ($self) = @_;

	my @txs = map { $_->to_serialized(witness => 0) } @{$self->transactions};

	Bitcoin::Crypto::Exception::Block->raise(
		'cannot calculate merkle root for empty block'
	) unless @txs > 0;

	# optimization - avoid checking thousands of bytestrings passed to merkle_root
	local $Bitcoin::Crypto::Types::CHECK_BYTESTRINGS = !!0;

	return scalar reverse Bitcoin::Crypto::Util::merkle_root(\@txs);
}

sub median_time_past
{
	my ($self) = @_;

	my @stamps;

	my $current = $self;
	for my $count (1 .. 11) {
		push @stamps, $current->timestamp;

		# NOTE: since we do not expect full blockchain to be available, exit
		# the loop early if we didn't get full 11 blocks required for MTP. Same
		# would happen if we had a full blockchain, but were using very early
		# blocks
		last unless $current->has_previous;
		$current = $current->previous;
	}

	@stamps = sort { $a <=> $b } @stamps;
	return $stamps[int(@stamps / 2)];
}

sub size
{
	my ($self) = @_;
	return length $self->to_serialized;
}

sub weight
{
	my ($self) = @_;

	my $base_size = length $self->to_serialized(witness => 0);
	my $total_size = length $self->to_serialized(witness => 1);

	# non-witness data is 4 times heavier than witness data
	return $base_size * 3 + $total_size;
}

signature_for verify => (
	method => !!1,
	named => [
	],
	bless => !!0,
);

# TODO: placeholder for actual block verification method. Not very usable and
# not documented yet.
sub verify
{
	my ($self, $args) = @_;

	# TODO: version 2 blocks with no coinbase height are only invalid if version 2
	# blocks are super-majority. There should be a consensus class to track that
	if ($self->version >= 2) {
		$self->clear_height;
		Bitcoin::Crypto::Exception::Block->raise(
			'coinbase transaction of version 2 block should contain height'
		) unless $self->has_height;
	}

	# TODO: to verify:
	# - block version
	# - block hex vs difficulty
	# - each transaction
	# - block subsidy
	# - BIP141 commitment structure in coinbase transaction
	# - probably more
	#
	# these verifications only make sense in full chain context though
}

sub dump
{
	my ($self) = @_;

	my $height_str = $self->has_height ? $self->height : 'unknown';

	my @result;
	push @result, 'Block ' . to_format [hex => $self->get_hash];
	push @result, 'height: ' . $height_str;
	push @result, 'version: ' . $self->version;
	push @result, 'previous: ' . to_format [hex => $self->prev_block_hash];
	push @result, 'merkle root: ' . to_format [hex => $self->merkle_root];
	push @result, 'timestamp: ' . $self->timestamp . ' (' . scalar(localtime($self->timestamp)) . ')';
	push @result, 'bits: 0x' . sprintf('%08x', $self->bits);
	push @result, 'nonce: ' . $self->nonce;
	push @result, 'size: ' . $self->size . ' bytes, ' . $self->weight . ' WU';
	push @result, '';

	push @result, @{$self->transactions} . ' transactions:';
	foreach my $tx (@{$self->transactions}) {
		push @result, $tx->dump;
		push @result, '';
	}

	return join "\n", @result;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Block - Bitcoin block implementation

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_block);
	use Bitcoin::Crypto::Util qw(to_format);

	# Create a new block
	my $block = btc_block->new(
		version => 1,
		prev_block_hash => $previous_hash,
		timestamp => 1697298600,
		bits => 0x1d00ffff,
		nonce => 12345,
		height => 812164,
	);

	# Add transactions
	$block->add_transaction($coinbase_tx);
	$block->add_transaction($tx1);
	$block->add_transaction($tx2);

	# Calculate merkle root
	my $merkle_root = $block->merkle_root;

	# Get block info
	print "Block hash: " . to_format([hex => $block->get_hash]) . "\n";
	print "Block size: " . $block->size . " bytes\n";
	print "Block weight: " . $block->weight . " WU\n";

	# Parse from serialized data
	my $block = btc_block->from_serialized($block_hex);

	# Serialize block
	my $serialized = $block->to_serialized;

	# For locktime and sequence checks
	my $next_block = btc_block->new(
		timestamp => 1697299200,
		height => 812165,
		previous => $block,
	);

	print $next_block->median_time_past;

=head1 DESCRIPTION

This is a complete Bitcoin block implementation that can parse, construct, and
serialize Bitcoin blocks. It supports all standard Bitcoin block operations
including transaction management, merkle root calculation, and block validation.

The class also provides the functionality required for locktime and sequence
checks in transactions, as used in L<Bitcoin::Crypto::Transaction/verify> and
L<Bitcoin::Crypto::Transaction::UTXO/block>. For transaction verification purposes,
only the L</timestamp>, L</height>, and optionally L</previous> attributes are
required - other block header fields can be omitted.

=head1 INTERFACE

=head2 Attributes

=head3 version

Block version number or version bits. Default: 1.

I<writer:> C<set_version>

I<Available in the constructor>.

=head3 prev_block_hash

Optional previous block hash as binary string (32 bytes)

I<Available in the constructor>.

I<writer:> C<set_prev_block_hash>

I<predicate:> C<has_prev_block_hash>

=head3 merkle_root

Merkle root hash as binary string (32 bytes). This field serves as a cache that
is calculated automatically and cleared on change of transactions. Calling
reader of this field repeatedly without adding new transactions via
L</add_transaction> or clearing it with the clearer will not cause the
recalculation of the merkle_root.

I<clearer:> C<clear_merkle_root>

=head3 timestamp

Block timestamp as Unix timestamp. Default: current time.

I<Available in the constructor>.

I<writer:> C<set_timestamp>

=head3 bits

Block difficulty target in compact notation. Default: 0x207fffff.

I<Available in the constructor>.

I<writer:> C<set_bits>

=head3 nonce

Block nonce used in proof-of-work. Default: 0.

I<Available in the constructor>.

I<writer:> C<set_nonce>

=head3 height

Optional block height. If the block has transactions, it will reach to the
first (coinbase) transaction and attempt to read it from it.

I<Available in the constructor>.

I<writer:> C<set_height>

I<predicate:> C<has_height>

I<clearer:> C<clear_height>

=head3 previous

An optional instance of the previous block. Note that setting a previous block
instance will automatically set L</prev_block_hash> if previous block has
transactions. It may silently replace the existing C<prev_block_hash>.

I<Available in the constructor>.

I<writer:> C<set_previous>

I<predicate:> C<has_previous>

=head3 transactions

Array reference of L<Bitcoin::Crypto::Transaction> objects contained in this block.
Use L</add_transaction> to add transactions.

=head2 Methods

=head3 new

	$block = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 has_transactions

	$bool = $object->has_transactions()

Returns a true value if the block object contains at least one transactions.
Using some methods (like L</merkle_root>) on block with no transactions will
raise an exception.

=head3 add_transaction

	$block = $object->add_transaction($transaction)
	$block = $object->add_transaction(@transaction_args)

Adds a transaction to the block. Can accept either a
L<Bitcoin::Crypto::Transaction> object or arguments to construct one.

Transaction will have its C<block> attribute set to this block.

Returns the block object for method chaining.

=head3 to_serialized

	$bytes = $object->to_serialized(%args)

Serializes the block into Bitcoin's binary format.

Available arguments:

=over

=item * C<witness> - boolean, whether to include witness data (default: true)

=back

Returns the serialized block as a binary string.

=head3 from_serialized

	$block = $class->from_serialized($bytes)

Creates a block object from serialized Bitcoin block data.

Takes the serialized block data as binary string. Does some basic validation of
the block: checks if a coinbase transaction exists, and if the merkle root
encoded in the serialized form matches the one calculated from transactions
(acting like a checksum check).

Returns a new block instance.

=head3 get_hash

	$hash = $object->get_hash()

Calculates and returns the block hash (double SHA-256 of the block header).

Returns the hash as a binary string in display format (big-endian).

=head3 get_header

	$header = $object->get_header()

Returns the 80-byte block header in Bitcoin's binary format.

=head3 size

	$size = $object->size()

Returns the size of the serialized block in bytes.

=head3 weight

	$weight = $object->weight()

Returns the block weight in weight units (WU).
Formula: base_size * 3 + total_size.

=head3 median_time_past

	$mtp = $object->median_time_past()

This method returns the median time past described in BIP113 (median timestamp
of previous 11 blocks).

Since this block implementation can be used without full chain, it will happily
calculate median time past from less than 11 blocks, if there aren't enough
blocks chained via L</previous>.

=head3 dump

	$string = $object->dump()

Returns a human-readable string representation of the block, including all
block header fields, metrics, and transaction summaries.

=head1 CAVEATS

Some details of block verification are curretly unimplemented. For example,
block subsidy is not validated. Note that to validate it, UTXOs for each of the
block's transactions must be known (to calculate fee) - so validating it will
only ever be possible in a full blockchain scenario.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=item L<Bitcoin::Crypto::Transaction::UTXO>

=back

=cut

