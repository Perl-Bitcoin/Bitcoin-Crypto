package Bitcoin::Crypto::Block;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Object PositiveInt PositiveOrZeroInt InstanceOf);

has param 'timestamp' => (
	isa => PositiveInt,
	default => sub { scalar time },
);

has param 'height' => (
	isa => PositiveOrZeroInt,
);

has option 'previous' => (
	isa => InstanceOf ['Bitcoin::Crypto::Block'],
);

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

1;

__END__
=head1 NAME

Bitcoin::Crypto::Block - Stripped down block instance

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_block);

	my $block = btc_block->new(
		timestamp => 1697298600,
		height => 812164,
	);

	my $next_block = btc_block->new(
		timestamp => 1697299200,
		height => 812165,
		previous => $block,
	);

	print $next_block->median_time_past;


=head1 DESCRIPTION

This is a block instance required for locktime and sequence checks in
transactions. It is used in L<Bitcoin::Crypto::Transaction/verify> and
L<Bitcoin::Crypto::Transaction::UTXO/block>.

Bitcoin::Crypto does not contain any real blocks implementation. This class
provides the bare minimum required for checking locktime and sequence.

=head1 INTERFACE

=head2 Attributes

=head3 height

An integer height of the block. Required.

I<Available in the constructor>.

=head3 timestamp

An integer timestamp of the block. Default - now.

I<Available in the constructor>.

=head3 previous

An optional instance of the previous block.

I<Available in the constructor>.

=head2 Methods

=head3 new

	$block = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 median_time_past

	$mtp = $object->median_time_past()

This method returns the median time past described in BIP113 (median timestamp
of the past 11 blocks).

Since this block implementation is as basic as it gets, it will happily
calculate median time past from less than 11 blocks, if there aren't enough
blocks chained via L</previous>.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=item L<Bitcoin::Crypto::Transaction::UTXO>

=back

=cut

