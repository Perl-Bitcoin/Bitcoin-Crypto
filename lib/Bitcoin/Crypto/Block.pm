package Bitcoin::Crypto::Block;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Types qw(PositiveInt PositiveOrZeroInt);

has param 'timestamp' => (
	isa => PositiveInt,
	default => sub { scalar time },
);

has param 'height' => (
	isa => PositiveOrZeroInt,
);

1;

