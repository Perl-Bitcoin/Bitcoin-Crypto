package Bitcoin::Crypto::Script::Recognition;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto::Helpers qw(standard_push);
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Script::Runner;

has param 'type' => (
	default => undef,
);

has param 'address' => (
	default => undef,
);

has param 'segwit_version' => (
	default => undef,
);

use constant {
	KIND_OPCODE => 1,
	KIND_NUMBER => 2,
	KIND_DATA => 3,
	KIND_REPEATED => 4,
	KIND_CHECK => 5,
};

sub _blueprints
{
	my ($class) = @_;

	state $blueprints = {};
	return $blueprints->{$class} //= $class->_build_blueprints;
}

sub _build_blueprints
{
	# blueprints for standard transaction types
	# constant size script types should be placed first so they are thrown away sooner
	# more common script types should be placed first so they can be found faster
	my @blueprints = (
		[
			'P2TR',
			[KIND_NUMBER, 'segwit_version', 1],
			[KIND_DATA, 'address', 32],
		],

		[
			'P2WPKH',
			[KIND_NUMBER, 'segwit_version', 0],
			[KIND_DATA, 'address', 20],
		],

		[
			'P2WSH',
			[KIND_NUMBER, 'segwit_version', 0],
			[KIND_DATA, 'address', 32],
		],

		[
			'P2PKH',
			'OP_DUP',
			'OP_HASH160',
			[KIND_DATA, 'address', 20],
			'OP_EQUALVERIFY',
			'OP_CHECKSIG',
		],

		[
			'P2SH',
			'OP_HASH160',
			[KIND_DATA, 'address', 20],
			'OP_EQUAL',
		],

		[
			'P2PK',
			[KIND_DATA, 'address', 33, 65],
			'OP_CHECKSIG',
		],

		[
			'UNKNOWN_SEGWIT',
			[KIND_NUMBER, 'segwit_version', 0 .. 16],
			[KIND_DATA, 'address', 2 .. 40],
		],

		[
			'NULLDATA',
			'OP_RETURN',
			[KIND_DATA, 'address', 1 .. 80],
		],

		[
			'P2MS',
			[KIND_NUMBER, 'sigs_number', 0 .. 20],
			[
				KIND_REPEATED,
				[KIND_DATA, 'addresses', 33, 65],
			],
			[KIND_NUMBER, 'pubkeys_number', 0 .. 20],
			sub {
				$_[0]->{vars}{addresses} //= [];
				$_[0]->{vars}{pubkeys_number} == @{$_[0]->{vars}{addresses}}
					&& $_[0]->{vars}{pubkeys_number} >= $_[0]->{vars}{sigs_number};
			},
			'OP_CHECKMULTISIG',
		],
	);

	my $preprocess_parts;
	$preprocess_parts = sub {
		my @parts = @_;

		foreach my $part (@parts) {
			if (ref $part eq 'ARRAY') {
				my ($kind, @vars) = @$part;

				if ($kind == KIND_DATA || $kind == KIND_NUMBER) {
					my $name = shift @vars;

					@vars = map { Bitcoin::Crypto::Script::Runner->from_int($_) } @vars
						if $kind == KIND_NUMBER;

					my %lookup = map { $_ => !!1 } @vars;
					$part = [$kind, $name, \%lookup];
				}
				elsif ($kind == KIND_REPEATED) {
					$part = [$kind, [$preprocess_parts->(@vars)]];
				}
				else {
					die "invalid blueprint kind: $kind";
				}
			}
			elsif (ref $part eq 'CODE') {
				$part = [KIND_CHECK, $part];
			}
			else {
				my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($part);
				$part = [KIND_OPCODE, $opcode->code];
			}
		}

		return @parts;
	};

	# pre-process blueprints for faster execution
	foreach my $variant (@blueprints) {
		my ($type, @parts) = @$variant;
		$variant = [$type, $preprocess_parts->(@parts)];
	}

	return \@blueprints;
}

sub _check_blueprint_segment
{
	my ($class, $ops, $parts, $state, $in_repeat_group) = @_;

	foreach my $part (@{$parts}) {
		my ($kind, @args) = @{$part};

		if ($kind == KIND_OPCODE || $kind == KIND_DATA || $kind == KIND_NUMBER) {
			my $op_data = $ops->[$state->{pos}];
			return 0 unless $op_data;

			if ($kind == KIND_OPCODE) {
				return 0 unless $args[0] == $op_data->[0]->code;
			}
			else {
				return 0 unless $op_data->[0]->pushop;
				return 0 unless standard_push($op_data->[0]->name, $op_data->[2]);

				my ($name, $lookup) = @args;
				my $value;

				if ($kind == KIND_DATA) {
					return 0 unless $lookup->{length $op_data->[2]};

					$value = $op_data->[2];
				}
				elsif ($kind == KIND_NUMBER) {
					return 0 unless $lookup->{$op_data->[2]};

					# numify bigint on 32 bit arch
					$value = '' . Bitcoin::Crypto::Script::Runner->to_int($op_data->[2]);
				}

				if ($in_repeat_group) {
					push @{$state->{vars}{$name}}, $value;
				}
				else {
					$state->{vars}{$name} = $value;
				}
			}

			$state->{pos} += 1;
		}
		elsif ($kind == KIND_REPEATED) {
			while (1) {

				# state copy avoids having temporary data stored inside
				# state if repeated part fails, as well as rewinding the
				# position to the last one which was valid
				my %state_cpy = %{$state};
				last unless $class->_check_blueprint_segment($ops, $args[0], \%state_cpy, 1);

				# commit state copy back into state (since matching succeded)
				%{$state} = %state_cpy;
			}
		}
		elsif ($kind == KIND_CHECK) {
			return 0 unless $args[0]->($state);
		}
	}

	return 1;
}

sub _check_blueprint
{
	my ($class, $ops, $blueprint) = @_;

	my ($type, @parts) = @{$blueprint};
	my %state = (
		pos => 0,
		vars => {},
	);

	return undef unless $class->_check_blueprint_segment($ops, \@parts, \%state);
	return undef unless $state{pos} == @{$ops};

	return $class->new(
		type => $type,
		address => $state{vars}{addresses} // $state{vars}{address},
		segwit_version => $state{vars}{segwit_version},
	);
}

sub check
{
	my ($class, $script) = @_;

	my $compiler = $script->_compiler;
	if (!$compiler->has_errors) {
		my $operations = $compiler->operations;

		foreach my $variant (@{$class->_blueprints}) {
			my $recognized = $class->_check_blueprint($operations, $variant);
			return $recognized if defined $recognized;
		}
	}

	# unknown
	return $class->new;
}

1;

