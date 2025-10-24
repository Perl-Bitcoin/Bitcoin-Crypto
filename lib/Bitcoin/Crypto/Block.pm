package Bitcoin::Crypto::Block;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Transaction;
use Bitcoin::Crypto::Util qw(pack_compactsize unpack_compactsize hash256 to_format);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

use namespace::clean;

# Block header fields
has param 'version' => (
	isa => IntMaxBits [32],
	default => 1,
);

has option 'prev_block_hash' => (
	isa => ByteStr,
);

has field 'merkle_root' => (
	isa => ByteStr,
	lazy => 1,
	builder => '_build_merkle_root',
	predicate => '_has_merkle_root',
	clearer => '_clear_merkle_root',
);

has param 'timestamp' => (
	isa => PositiveInt,
	default => sub { scalar time },
);

has param 'bits' => (
	isa => IntMaxBits [32],
	default => 0x207fffff,    # Difficulty bits
);

has param 'nonce' => (
	isa => IntMaxBits [32],
	default => 0,
);

has param 'height' => (
	isa => PositiveOrZeroInt,
);

has option 'previous' => (
	isa => InstanceOf ['Bitcoin::Crypto::Block'],
);

has field 'transactions' => (
	isa => ArrayRef [InstanceOf ['Bitcoin::Crypto::Transaction']],
	default => sub { [] },
);

signature_for add_transaction => (
	method => Object,
	positional => [ArrayRef, {slurpy => !!1}],
);

sub add_transaction
{
	my ($self, $data) = @_;

	if (@$data == 1) {
		$data = $data->[0];

		Bitcoin::Crypto::Exception::Block->raise(
			'expected a transaction object'
		) unless blessed $data && $data->isa('Bitcoin::Crypto::Transaction');
	}
	else {
		$data = Bitcoin::Crypto::Transaction->new(@$data);
	}

	push @{$self->transactions}, $data;

	# Clear cached merkle root if set
	$self->_clear_merkle_root if $self->_has_merkle_root;

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

	my $serialized = '';

	# Block header (80 bytes)
	$serialized .= pack 'V', $self->version;
	$serialized .= scalar reverse $self->prev_block_hash;    # Reversed for little-endian
	$serialized .= scalar reverse $self->merkle_root;    # Reversed for little-endian
	$serialized .= pack 'V', $self->timestamp;
	$serialized .= pack 'V', $self->bits;
	$serialized .= pack 'V', $self->nonce;

	# Transaction count
	$serialized .= pack_compactsize(scalar @{$self->transactions});

	# Transactions
	foreach my $tx (@{$self->transactions}) {
		$serialized .= $tx->to_serialized(witness => $args->{witness});
	}

	return $serialized;
}

signature_for from_serialized => (
	method => Str,
	positional => [
		ByteStr,
		Maybe [PositiveOrZeroInt], {default => undef},
	],
);

sub from_serialized
{
	my ($class, $serialized, $height) = @_;
	my $pos = 0;

	Bitcoin::Crypto::Exception::Block->raise(
		'serialized block data too short for header'
	) if length($serialized) < 80;

	# Parse block header (80 bytes)
	my $version = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	my $prev_block_hash = scalar reverse substr $serialized, $pos, 32;
	$pos += 32;

	my $merkle_root = scalar reverse substr $serialized, $pos, 32;
	$pos += 32;

	my $timestamp = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	my $bits = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	my $nonce = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	# Parse transaction count
	my $tx_count = unpack_compactsize $serialized, \$pos;

	# Parse transactions
	my @transactions;
	for my $tx_index (1 .. $tx_count) {
		Bitcoin::Crypto::Exception::Block->raise(
			'unexpected end of block data while parsing transactions'
		) if $pos >= length($serialized);

		my $tx_start = $pos;
		my $tx_pos = $pos;

		# Version (4 bytes)
		$tx_pos += 4;

		# Check for witness flag
		my $witness_flag = 0;
		if ($tx_pos + 2 <= length($serialized)) {
			$witness_flag = (substr($serialized, $tx_pos, 2) eq "\x00\x01");
			$tx_pos += 2 if $witness_flag;
		}

		# Parse input count and inputs
		my $input_count = unpack_compactsize $serialized, \$tx_pos;
		for (1 .. $input_count) {
			$tx_pos += 32;    # Previous transaction hash
			$tx_pos += 4;    # Previous transaction index

			my $script_length = unpack_compactsize $serialized, \$tx_pos;
			$tx_pos += $script_length;    # Script
			$tx_pos += 4;    # Sequence
		}

		# Parse output count and outputs
		my $output_count = unpack_compactsize $serialized, \$tx_pos;
		for (1 .. $output_count) {
			$tx_pos += 8;    # Value

			my $script_length = unpack_compactsize $serialized, \$tx_pos;
			$tx_pos += $script_length;    # Script
		}

		# Parse witness data if present
		if ($witness_flag) {
			for (1 .. $input_count) {
				my $input_witness_count = unpack_compactsize $serialized, \$tx_pos;
				for (1 .. $input_witness_count) {
					my $witness_item_length = unpack_compactsize $serialized, \$tx_pos;
					$tx_pos += $witness_item_length;
				}
			}
		}

		# Locktime (4 bytes)
		$tx_pos += 4;

		# Extract and parse transaction
		my $tx_length = $tx_pos - $tx_start;
		my $tx_data = substr($serialized, $tx_start, $tx_length);
		my $tx = Bitcoin::Crypto::Transaction->from_serialized($tx_data);

		$pos = $tx_pos;
		push @transactions, $tx;
	}

	Bitcoin::Crypto::Exception::Block->raise(
		'serialized block data is corrupted'
	) if $pos != length $serialized;

	my $block_args = {
		version => $version,
		prev_block_hash => $prev_block_hash,
		timestamp => $timestamp,
		bits => $bits,
		nonce => $nonce,
	};

	# Add height if provided
	$block_args->{height} = $height if defined $height;

	my $block = $class->new($block_args);
	@{$block->transactions} = @transactions;
	$block->{merkle_root} = $merkle_root;

	return $block;
}

signature_for get_hash => (
	method => Object,
	positional => [],
);

sub get_hash
{
	my ($self) = @_;
	return scalar reverse hash256($self->get_header);
}

signature_for get_header => (
	method => Object,
	positional => [],
);

sub get_header
{
	my ($self) = @_;

	# Return just the 80-byte block header
	my $header = '';
	$header .= pack 'V', $self->version;
	$header .= scalar reverse $self->prev_block_hash;
	$header .= scalar reverse $self->merkle_root;
	$header .= pack 'V', $self->timestamp;
	$header .= pack 'V', $self->bits;
	$header .= pack 'V', $self->nonce;

	return $header;
}

sub _build_merkle_root
{
	my ($self) = @_;

	my @tx_hashes = map { scalar reverse $_->get_hash } @{$self->transactions};

	Bitcoin::Crypto::Exception::Block->raise(
		'cannot calculate merkle root for empty block'
	) unless @tx_hashes;

	# Build merkle tree
	while (@tx_hashes > 1) {
		my @next_level;

		for (my $i = 0 ; $i < @tx_hashes ; $i += 2) {
			my $left = $tx_hashes[$i];
			my $right = $i + 1 < @tx_hashes ? $tx_hashes[$i + 1] : $left;

			# Concatenate and double hash
			push @next_level, hash256($left . $right);
		}

		@tx_hashes = @next_level;
	}

	return scalar reverse $tx_hashes[0];
}

signature_for median_time_past => (
	method => Object,
	positional => [],
);

sub median_time_past
{
	my ($self) = @_;

	my @stamps;

	my $current = $self;
	for my $count (1 .. 11) {
		push @stamps, $current->timestamp;

		# NOTE: since we do not expect full blockchain to be available, exit
		# the loop early if we didn't get full 11 blocks required for MTP.
		# Should this warn?
		last unless $current->has_previous;
		$current = $current->previous;
	}

	@stamps = sort { $a <=> $b } @stamps;
	return $stamps[int(@stamps / 2)];
}

signature_for size => (
	method => Object,
	positional => [],
);

sub size
{
	my ($self) = @_;
	return length $self->to_serialized;
}

signature_for weight => (
	method => Object,
	positional => [],
);

sub weight
{
	my ($self) = @_;

	# Block weight = base size * 3 + total size
	my $base_size = length $self->to_serialized(witness => 0);
	my $total_size = length $self->to_serialized(witness => 1);

	return $base_size * 3 + $total_size;
}

signature_for dump => (
	method => Object,
	positional => [],
);

sub dump
{
	my ($self) = @_;

	my $height_str = defined $self->height ? $self->height : 'unknown';

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
	my $block = btc_block->from_serialized($block_hex, $height);

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

Block version number. Default: 1.

I<Available in the constructor>.

=head3 prev_block_hash

Previous block hash as binary string (32 bytes). Default: 32 zero bytes.

I<Available in the constructor>.

=head3 merkle_root

Merkle root hash as binary string (32 bytes). Default: 32 zero bytes.
Can be calculated automatically using L</calculate_merkle_root>.

I<Available in the constructor>.

=head3 timestamp

Block timestamp as Unix timestamp. Default: current time.

I<Available in the constructor>.

=head3 bits

Block difficulty target in compact notation. Default: 0x207fffff.

I<Available in the constructor>.

=head3 nonce

Block nonce used in proof-of-work. Default: 0.

I<Available in the constructor>.

=head3 height

Block height

I<Available in the constructor>.

=head3 previous

An optional instance of the previous block.

I<Available in the constructor>.

=head3 transactions

Array reference of L<Bitcoin::Crypto::Transaction> objects contained in this block.
Use L</add_transaction> to add transactions.

=head2 Methods

=head3 new

	$block = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 add_transaction

	$block = $object->add_transaction($transaction)
	$block = $object->add_transaction(@transaction_args)

Adds a transaction to the block. Can accept either a 
L<Bitcoin::Crypto::Transaction> object or arguments to construct one.

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

	$block = $class->from_serialized($bytes, $height)

Creates a block object from serialized Bitcoin block data.

Takes the serialized block data as binary string and the block height.

Returns a new block instance.

=head3 get_hash

	$hash = $object->get_hash()

Calculates and returns the block hash (double SHA-256 of the block header).

Returns the hash as a binary string in display format (big-endian).

=head3 get_header

	$header = $object->get_header()

Returns the 80-byte block header in Bitcoin's binary format.

=head3 merkle_root

	$merkle_root = $object->merkle_root()

Calculates the merkle root from the block's transactions.
Throws an exception if the block has no transactions.

Returns the calculated merkle root.

=head3 size

	$size = $object->size()

Returns the size of the serialized block in bytes.

=head3 weight

	$weight = $object->weight()

Returns the block weight in weight units (WU).
Formula: base_size * 3 + total_size.

=head3 dump

	$string = $object->dump()

Returns a human-readable string representation of the block, including all
block header fields, metrics, and transaction summaries.

=head3 median_time_past

	$mtp = $object->median_time_past()

This method returns the median time past described in BIP113 (median timestamp
of previous 11 blocks).

Since this block implementation is as basic as it gets, it will happily
calculate median time past from less than 11 blocks, if there aren't enough
blocks chained via L</previous>.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=item L<Bitcoin::Crypto::Transaction::UTXO>

=back

=cut

