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
		# early if we didn't get full 11 blocks required for MTP. Should this
		# warn?
		last unless $current->has_previous;
		$current = $current->previous;
	}

	@stamps = sort { $a <=> $b } @stamps;
	return $stamps[int(@stamps / 2)];
}

1;

