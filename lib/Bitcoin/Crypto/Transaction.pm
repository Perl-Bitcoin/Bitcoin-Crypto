package Bitcoin::Crypto::Transaction;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(IntMaxBits ArrayRef InstanceOf);

has param 'version' => (
	isa => IntMaxBits[32],
	default => 1,
);

has field 'inputs' => (
	isa => ArrayRef[InstanceOf['Bitcoin::Crypto::Transaction::Input']],
);

has field 'outputs' => (
	isa => ArrayRef[InstanceOf['Bitcoin::Crypto::Transaction::Output']],
);

has param 'locktime' => (
	isa => IntMaxBits[32],
	default => 1,
);

sub to_serialized
{
	my ($self) = @_;

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

	$serialized .= pack_varint(scalar @inputs);
	foreach my $item (@inputs) {
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

	$serialized .= pack 'V', $self->locktime;

	return $serialized;
}

1;

