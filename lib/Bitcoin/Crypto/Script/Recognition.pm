package Bitcoin::Crypto::Script::Recognition;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Helpers qw(standard_push);
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Script::Runner;

has param 'script' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script'],
	weak_ref => 1,
);

has field 'type' => (
	writer => 1,
);

has field 'address' => (
	writer => 1,
);

has field 'segwit_version' => (
	writer => 1,
);

use constant {
	KIND_OPCODE => 1,
	KIND_SEGWIT_VERSION => 2,
	KIND_NUMBER => 3,
	KIND_ADDRESS => 4,
	KIND_DATA => 5,
	KIND_DATA_REPEATED => 6,
};

sub _blueprints
{
	my ($self) = @_;
	my $class = ref $self || $self;

	state $blueprints = {};
	return $blueprints->{$class} //= $self->_build_blueprints;
}

sub _build_blueprints
{
	# blueprints for standard transaction types
	# constant size script types should be placed first so they are thrown away sooner
	# more common script types should be placed first so they can be found faster
	my @blueprints = (
		[
			P2TR => [
				[KIND_SEGWIT_VERSION, 1],
				[KIND_ADDRESS, 32],
			]
		],

		[
			P2WPKH => [
				[KIND_SEGWIT_VERSION, 0],
				[KIND_ADDRESS, 20],
			],
		],

		[
			P2WSH => [
				[KIND_SEGWIT_VERSION, 0],
				[KIND_ADDRESS, 32],
			]
		],

		[
			P2PKH => [
				'OP_DUP',
				'OP_HASH160',
				[KIND_ADDRESS, 20],
				'OP_EQUALVERIFY',
				'OP_CHECKSIG',
			]
		],

		[
			P2SH => [
				'OP_HASH160',
				[KIND_ADDRESS, 20],
				'OP_EQUAL',
			]
		],

		[
			P2PK => [
				[KIND_DATA, 33, 65],
				'OP_CHECKSIG',
			]
		],

		[
			'UNKNOWN_SEGWIT' => [
				[KIND_SEGWIT_VERSION, 0 .. 16],
				[KIND_DATA, 2 .. 40],
			],
		],

		[
			NULLDATA => [
				'OP_RETURN',
				[KIND_ADDRESS, 1 .. 80],
			]
		],

		[
			P2MS => [
				[KIND_NUMBER, 0 .. 20],
				[KIND_DATA_REPEATED, 33, 65],
				[KIND_NUMBER, 0 .. 20],
				'OP_CHECKMULTISIG',
			]
		],
	);

	# pre-process blueprints for faster execution
	foreach my $variant (@blueprints) {
		my ($type, $parts) = @$variant;

		foreach my $part (@$parts) {
			if (ref $part) {
				my ($kind, @vars) = @$part;

				if ($kind == KIND_ADDRESS || $kind == KIND_DATA) {

					# no special handling
				}
				elsif ($kind == KIND_DATA_REPEATED) {

					# no special handling
				}
				elsif ($kind == KIND_NUMBER || $kind == KIND_SEGWIT_VERSION) {
					@vars = map { Bitcoin::Crypto::Script::Runner->from_int($_) } @vars;
				}
				else {
					die "invalid blueprint kind: $kind";
				}

				my %lookup = map { $_ => !!1 } @vars;
				$part = [$kind, \%lookup];
			}
			else {
				my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($part);
				$part = [KIND_OPCODE, $opcode->code];
			}
		}
	}

	return \@blueprints;
}

sub _check_blueprint
{
	my ($self, $ops, $type, $parts) = @_;

	my $parts_size = @{$parts};
	my $pos = 0;

	my $address;
	my $segwit_version;

	foreach my $part (@{$parts}) {
		my ($kind, $lookup) = @{$part};
		my $op_data = $ops->[$pos];
		return !!0 unless $op_data;

		if ($kind == KIND_OPCODE) {
			return !!0 unless $lookup == $op_data->[0]->code;
		}
		elsif ($kind == KIND_ADDRESS || $kind == KIND_DATA) {
			return !!0 unless $op_data->[0]->pushop;
			my $len = length $op_data->[2];

			return !!0 unless $lookup->{$len};
			return !!0 unless standard_push($op_data->[0]->name, $op_data->[2]);
			$address = $op_data->[2]
				if $kind == KIND_ADDRESS;
		}
		elsif ($kind == KIND_NUMBER || $kind == KIND_SEGWIT_VERSION) {
			return !!0 unless $op_data->[0]->pushop;
			return !!0 unless $lookup->{$op_data->[2]};
			return !!0 unless standard_push($op_data->[0]->name, $op_data->[2]);

			if ($kind == KIND_SEGWIT_VERSION) {

				# numify bigint on 32 bit arch
				$segwit_version = '' . Bitcoin::Crypto::Script::Runner->to_int($op_data->[2]);
			}
		}
		elsif ($kind == KIND_DATA_REPEATED) {
			my $count = 0;
			while (1) {
				return !!0 unless $op_data && $op_data->[0]->pushop;
				return !!0 unless standard_push($op_data->[0]->name, $op_data->[2]);
				my $len = length $op_data->[2];
				last unless $lookup->{$len};

				$pos += 1;
				$op_data = $ops->[$pos];
				$count += 1;
			}

			return !!0 unless $op_data->[0]->pushop;
			return !!0 unless Bitcoin::Crypto::Script::Runner->from_int($count) eq $op_data->[2];

			# check the same opcode again with next blueprint part
			next;
		}

		++$pos;
	}

	return !!0 unless $pos == @{$ops};

	$self->set_address($address);
	$self->set_segwit_version($segwit_version);
	$self->set_type($type);

	return !!1;
}

sub check
{
	my ($self) = @_;

	my $compiler = $self->script->_compiler;
	return if $compiler->has_errors;
	my $operations = $compiler->operations;

	foreach my $variant (@{$self->_blueprints}) {
		last if $self->_check_blueprint($operations, @{$variant});
	}

	return;
}

1;

