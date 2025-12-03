package Bitcoin::Crypto::Script::Recognition;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;
use List::Util qw(any min max);

use Bitcoin::Crypto::Script::Opcode;

has param 'script' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script'],
	weak_ref => 1,
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

has field 'segwit_version' => (
	predicate => 1,
	writer => 1,
	clearer => 1,
);

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
				['segwit_version', 1],
				['address', 32],
			]
		],

		[
			P2WPKH => [
				['segwit_version', 0],
				['address', 20],
			],
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
			P2WSH => [
				['segwit_version', 0],
				['address', 32],
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
			P2PK => [
				['data', 33, 65],
				'OP_CHECKSIG',
			]
		],

		[
			'UNKNOWN_SEGWIT' => [
				['segwit_version', 0 .. 16],
				['data', 2 .. 40],
			],
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

		# TODO: P2MS suports up to 20 pubkeys / sigs (need better implementation)
		[
			P2MS => [
				['op_n', 0 .. 16],
				['data_repeated', 33, 65],
				['op_n', 0 .. 16],
				'OP_CHECKMULTISIG',
			]
		],
	);

	# pre-process blueprints for faster execution
	foreach my $variant (@blueprints) {
		my ($type, $parts) = @$variant;
		my $len_min = 0;
		my $len_max = 0;

		foreach my $part (@$parts) {
			if (ref $part) {
				my ($kind, @vars) = @$part;

				if ($kind eq 'address' || $kind eq 'data') {
					$len_min += 1 + min @vars;
					$len_max += 1 + max @vars
						if defined $len_max;
				}
				elsif ($kind eq 'data_repeated') {
					$len_max = undef;
				}
				elsif ($kind eq 'op_n' || $kind eq 'segwit_version') {
					my @codes = map { Bitcoin::Crypto::Script::Opcode->get_opcode_by_name("OP_$_") } @vars;
					$part = [$kind, @codes];
					$len_min += 1;
					$len_max += 1
						if defined $len_max;
				}
				else {
					die "invalid blueprint kind: $kind";
				}
			}
			else {
				my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($part);
				$part = ['byte', $opcode];

				$len_min += 1;
				$len_max += 1
					if defined $len_max;
			}
		}

		push @$variant, $len_min, $len_max;
	}

	return \@blueprints;
}

sub _check_blueprint
{
	my ($self, $this_script, $pos, $part, @more_parts) = @_;

	return $pos == length $this_script
		unless defined $part;
	return !!0 unless $pos < length $this_script;

	my ($kind, @vars) = @$part;

	if ($kind eq 'byte') {
		return !!0 unless chr $vars[0]->code eq substr $this_script, $pos, 1;
		return $self->_check_blueprint($this_script, $pos + 1, @more_parts);
	}
	elsif ($kind eq 'address' || $kind eq 'data') {
		my $len = ord substr $this_script, $pos, 1;

		return !!0 unless any { $_ == $len } @vars;
		if ($self->_check_blueprint($this_script, $pos + $len + 1, @more_parts)) {
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

		return !!0 if $count > 16;
		my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name("OP_$count");
		return !!0 unless chr $opcode->code eq substr $this_script, $pos, 1;
		return $self->_check_blueprint($this_script, $pos, @more_parts);
	}
	elsif ($kind eq 'op_n' || $kind eq 'segwit_version') {
		my $byte = ord substr $this_script, $pos, 1;
		my $found;

		foreach my $opcode (@vars) {
			next unless $byte eq $opcode->code;
			$found = $opcode;
			last;
		}

		return !!0 unless $found;

		if ($kind eq 'segwit_version') {
			$found->name =~ /^OP_(\d+)$/;
			$self->set_segwit_version($1);
		}

		return $self->_check_blueprint($this_script, $pos + 1, @more_parts);
	}
}

sub check
{
	my ($self) = @_;

	my $script = $self->script->to_serialized;
	my $len = length $script;

	foreach my $variant (@{$self->_blueprints}) {
		my ($type, $blueprint, $min_len, $max_len) = @{$variant};

		next unless $len >= $min_len && (!defined($max_len) || $len <= $max_len);

		if ($self->_check_blueprint($script, 0, @{$blueprint})) {
			$self->set_type($type);
			last;
		}
		else {
			# clear data
			$self->clear_address;
			$self->clear_segwit_version;
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

sub get_segwit_version
{
	my ($self) = @_;

	$self->check;
	return $self->segwit_version;
}

1;

