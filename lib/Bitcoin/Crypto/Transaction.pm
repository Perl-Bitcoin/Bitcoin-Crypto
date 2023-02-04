package Bitcoin::Crypto::Transaction;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Types qw(PositiveIntArrayRef InstanceOf);

has param 'version' => (
	isa => PositiveInt,
	default => 1,
);

has field 'inputs' => (
	isa => ArrayRef[InstanceOf['Bitcoin::Crypto::Transaction::Input']],
);

has field 'outputs' => (
	isa => ArrayRef[InstanceOf['Bitcoin::Crypto::Transaction::Output']],
);

1;

