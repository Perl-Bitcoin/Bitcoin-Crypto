package Bitcoin::Crypto::Script::Recognition;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types;
use List::Util qw(any);
use Try::Tiny;

use Bitcoin::Crypto::Script::Opcode;

has param 'script' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script'],
);

has field '_script_serialized' => (
	lazy => sub { $_[0]->script->to_serialized },
);

has field 'type' => (
	predicate => 1,
	writer => 1,
);

has field 'address' => (
	predicate => 1,
	writer => 1,
	clearer => 1,
);

has field '_blueprints' => (
	builder => 1,
);

sub _build_blueprints
{
	# blueprints for standard transaction types
	return [
		[
			P2PK => [
				['data', 33, 65],
				'OP_CHECKSIG',
			]
		],

		[
			P2PKH => [
				'OP_DUP',
				'OP_HASH160',
				['address', 20],
				'OP_EQUALVERIFY',
				'OP_CHECKSIG',
			]
		],

		[
			P2SH => [
				'OP_HASH160',
				['address', 20],
				'OP_EQUAL',
			]
		],

		[
			P2MS => [
				['op_n', 1 .. 15],
				['data_repeated', 33, 65],
				['op_n', 1 .. 15],
				'OP_CHECKMULTISIG',
			]
		],

		[
			P2WPKH => [
				'OP_0',
				['address', 20],
			],
		],

		[
			P2WSH => [
				'OP_0',
				['address', 32],
			]
		],

		[
			P2TR => [
				'OP_1',
				['address', 32],
			]
		],

		[
			NULLDATA => [
				'OP_RETURN',
				['address', 1 .. 75],
			]
		],

		[
			NULLDATA => [
				'OP_RETURN',
				'OP_PUSHDATA1',
				['address', 76 .. 80],
			]
		],
	];
}

sub _check_blueprint
{
	my ($self, $pos, $part, @more_parts) = @_;
	my $this_script = $self->_script_serialized;

	return $pos == length $this_script
		unless defined $part;
	return !!0 unless $pos < length $this_script;

	if (!ref $part) {
		my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($part);
		return !!0 unless chr($opcode->code) eq substr $this_script, $pos, 1;
		return $self->_check_blueprint($pos + 1, @more_parts);
	}
	else {
		my ($kind, @vars) = @$part;

		if ($kind eq 'address' || $kind eq 'data') {
			my $len = ord substr $this_script, $pos, 1;

			return !!0 unless any { $_ == $len } @vars;
			if ($self->_check_blueprint($pos + $len + 1, @more_parts)) {
				$self->set_address(substr $this_script, $pos + 1, $len)
					if $kind eq 'address';
				return !!1;
			}
		}
		elsif ($kind eq 'data_repeated') {
			my $count = 0;
			while (1) {
				my $len = ord substr $this_script, $pos, 1;
				last unless any { $_ == $len } @vars;

				$pos += $len + 1;
				$count += 1;
			}

			return !!0 if $count == 0 || $count > 16;
			my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name("OP_$count");
			return !!0 unless chr($opcode->code) eq substr $this_script, $pos, 1;
			return $self->_check_blueprint($pos, @more_parts);
		}
		elsif ($kind eq 'op_n') {
			my $opcode;
			try {
				$opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_code(ord substr $this_script, $pos, 1);
			};

			return !!0 unless $opcode;
			return !!0 unless $opcode->name =~ /\AOP_(\d+)\z/;
			return !!0 unless any { $_ == $1 } @vars;
			return $self->_check_blueprint($pos + 1, @more_parts);
		}
		else {
			die "invalid blueprint kind: $kind";
		}
	}
}

sub check
{
	my ($self) = @_;
	foreach my $variant (@{$self->_blueprints}) {
		my ($type, $blueprint) = @{$variant};

		# clear address if it was set by previous check
		$self->clear_address;
		if ($self->_check_blueprint(0, @{$blueprint})) {
			$self->set_type($type);
			last;
		}
	}

	return;
}

sub get_type
{
	my ($self) = @_;

	$self->check;
	return $self->type;
}

sub get_address
{
	my ($self) = @_;

	$self->check;
	return $self->address;
}

1;

