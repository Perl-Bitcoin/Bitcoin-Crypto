package Bitcoin::Crypto::Script;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;
use Crypt::Digest::SHA256 qw(sha256);
use Scalar::Util qw(blessed);
use List::Util qw(any);
use Carp qw(carp);

use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit decode_segwit get_hrp);
use Bitcoin::Crypto::Constants qw(:witness);
use Bitcoin::Crypto::Util::Internal qw(hash160 hash256 get_address_type to_format);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Script::Compiler;
use Bitcoin::Crypto::Script::Common;
use Bitcoin::Crypto::Script::Recognition;

has field '_serialized' => (
	isa => ByteStr,
	writer => 1,
	default => '',
);

has field '_recognition' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Recognition'],
	lazy => 1,
	clearer => -hidden,
	handles => {
		get_raw_address => 'address',
		type => 'type',
		segwit_version => 'segwit_version',
	},
);

has field '_compiler' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Compiler'],
	lazy => 1,
	clearer => -hidden,
	handles => {
		operations => 'operations',
		has_errors => 'has_errors',
		assert_valid => 'assert_valid',
	},
);

with qw(Bitcoin::Crypto::Role::Network);

sub _build_recognition
{
	return Bitcoin::Crypto::Script::Recognition->check(shift);
}

sub _build_compiler
{
	return Bitcoin::Crypto::Script::Compiler->compile(shift);
}

sub _build
{
	my ($self, $type, $address) = @_;

	state $types = do {
		my $legacy = sub {
			my ($self, $address, $type) = @_;

			my $decoded = decode_base58check($address);
			my $network_byte = substr $decoded, 0, 1, '';

			Bitcoin::Crypto::Exception::Address->raise(
				"legacy scripts should contain 20 bytes"
			) unless length $decoded == 20;

			my $byte_method = lc "p2${type}_byte";
			Bitcoin::Crypto::Exception::NetworkCheck->raise(
				"provided address $address is not P2$type on network " . $self->network->name
			) if $network_byte ne $self->network->$byte_method;

			Bitcoin::Crypto::Script::Common->fill($type => $self, $decoded);
		};

		my $witness = sub {
			my ($self, $address, $name, $version, $length) = @_;

			my $data = decode_segwit $address;
			my $this_version = substr $data, 0, 1, '';

			Bitcoin::Crypto::Exception::SegwitProgram->raise(
				"$name script only handles witness version $version"
			) unless $this_version eq chr $version;

			Bitcoin::Crypto::Exception::SegwitProgram->raise(
				"$name script should contain $length bytes"
			) unless length $data eq $length;

			Bitcoin::Crypto::Exception::NetworkCheck->raise(
				"provided address $address does not belong to network " . $self->network->name
			) if get_hrp($address) ne $self->network->segwit_hrp;

			$self
				->add("OP_$version")
				->push($data);
		};

		{
			P2PK => sub {
				my ($self, $pubkey) = @_;

				$self
					->push($pubkey)
					->add('OP_CHECKSIG');
			},

			P2PKH => sub {
				$legacy->(@_, 'PKH');
			},

			P2SH => sub {
				$legacy->(@_, 'SH');
			},

			P2MS => sub {
				my ($self, $data) = @_;

				Bitcoin::Crypto::Exception::ScriptPush->raise(
					'P2MS script argument must be an array reference'
				) unless ref $data eq 'ARRAY';

				my ($signatures_num, @pubkeys) = @$data;

				Bitcoin::Crypto::Exception::ScriptPush->raise(
					'P2MS script first element must be a number between 1 and 15'
				) unless $signatures_num >= 0 && $signatures_num <= 15;

				Bitcoin::Crypto::Exception::ScriptPush->raise(
					'P2MS script remaining elements number should be between the number of signatures and 15'
				) unless @pubkeys >= $signatures_num && @pubkeys <= 15;

				$self->push(chr $signatures_num);

				foreach my $pubkey (@pubkeys) {
					$self->push($pubkey);
				}

				$self
					->push(chr scalar @pubkeys)
					->add('OP_CHECKMULTISIG');
			},

			P2WPKH => sub {
				$witness->(@_, 'P2WPKH', 0, 20);
			},

			P2WSH => sub {
				$witness->(@_, 'P2WSH', 0, 32);
			},

			P2TR => sub {
				$witness->(@_, 'P2TR', 1, 32);
			},

			NULLDATA => sub {
				my ($self, $data) = @_;

				$self
					->add('OP_RETURN')
					->push($data);
			},
		};
	};

	Bitcoin::Crypto::Exception::ScriptType->raise(
		"unknown standard script type $type"
	) if !$types->{$type};

	$types->{$type}->($self, $address);
	return;
}

sub opcode_class
{
	return 'Bitcoin::Crypto::Script::Opcode';
}

sub BUILD
{
	my ($self, $args) = @_;

	if ($args->{type}) {
		Bitcoin::Crypto::Exception::ScriptPush->raise(
			'script with a "type" also requires an "address"'
		) unless $args->{address};

		$self->_build($args->{type}, $args->{address});
	}
}

sub is_pushes_only
{
	my ($self) = @_;

	foreach my $op (@{$self->operations}) {
		return !!0 if $op->[0]->non_push_opcode;
	}

	return !!1;
}

# same as add_raw, but does not clear the object - to avoid clearing it
# multiple times per operation
sub _add_raw
{
	my ($self, $bytes) = @_;

	$self->_set_serialized($self->_serialized . $bytes);
}

signature_for add_raw => (
	method => !!1,
	positional => [ByteStr],
);

sub add_raw
{
	my ($self, $bytes) = @_;

	$self->_add_raw($bytes);
	$self->_clear_compiler;
	$self->_clear_recognition;
	return $self;
}

signature_for add_operation => (
	method => !!1,
	positional => [Str],
);

sub add_operation
{
	my ($self, $name) = @_;

	my $opcode = $self->opcode_class->get_opcode_by_name($name);
	$self->add_raw(chr $opcode->code);

	return $self;
}

sub add
{
	goto \&add_operation;
}

signature_for push_bytes => (
	method => !!1,
	positional => [ByteStr],
);

sub push_bytes
{
	my ($self, $bytes) = @_;

	my $len = length $bytes;

	if ($len == 0) {
		return $self->add_operation('OP_0');
	}
	elsif ($len == 1) {
		my $ord = ord($bytes);

		if ($ord <= 0x10 && $ord != 0) {
			return $self->add_operation("OP_$ord");
		}
		elsif ($ord == 0x81) {
			return $self->add_operation('OP_1NEGATE');
		}
	}

	if ($len <= 75) {
		$self
			->_add_raw(pack 'Ca*', $len, $bytes);
	}
	elsif ($len <= 0xff) {
		$self
			->add_operation('OP_PUSHDATA1')
			->_add_raw(pack 'Ca*', $len, $bytes);
	}
	elsif ($len <= 0xffff) {
		$self
			->add_operation('OP_PUSHDATA2')
			->_add_raw(pack 'va*', $len, $bytes);
	}
	elsif ($len <= 0xffffffff) {
		$self
			->add_operation('OP_PUSHDATA4')
			->_add_raw(pack 'Va*', $len, $bytes);
	}
	else {
		Bitcoin::Crypto::Exception::ScriptPush->raise(
			'too much data to push onto stack in one operation'
		);
	}

	return $self;
}

signature_for push_number => (
	method => !!1,
	positional => [Int | Str | InstanceOf ['Math::BigInt']],
);

sub push_number
{
	my ($self, $number) = @_;

	return $self->push_bytes(Bitcoin::Crypto::Script::Runner->from_int($number));
}

sub push
{
	goto \&push_bytes;
}

# this can only detect native segwit in this context, as P2SH outputs are
# indistinguishable from any other P2SH
sub is_native_segwit
{
	return defined shift->segwit_version;
}

sub is_taproot
{
	return (shift->type // '') eq 'P2TR';
}

sub get_hash
{
	return hash160(shift->_serialized);
}

sub to_serialized
{
	goto \&_serialized;
}

signature_for from_serialized => (
	method => !!1,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $bytes) = @_;

	my $self = $class->new;
	$self->_set_serialized($bytes);
	return $self;
}

signature_for from_standard => (
	method => !!1,
	positional => [ScriptDesc, {slurpy => !!1}],
);

sub from_standard
{
	my ($class, $desc) = @_;

	if ($desc->[0] eq 'address') {
		$desc->[0] = get_address_type($desc->[1]);
	}

	return $class->new(
		type => $desc->[0],
		address => $desc->[1],
	);
}

signature_for run => (
	method => !!1,
	positional => [ArrayRef [ByteStr], {default => []}],
);

sub run
{
	my ($self, $initial_stack) = @_;

	my $runner = Bitcoin::Crypto::Script::Runner->new();
	return $runner->execute($self, $initial_stack);
}

sub witness_program
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program
		->add_operation('OP_' . SEGWIT_WITNESS_VERSION)
		->push_bytes(sha256($self->to_serialized));

	return $program;
}

sub get_legacy_address
{
	my ($self) = @_;
	return encode_base58check($self->network->p2sh_byte . $self->get_hash);
}

sub get_compat_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	return $self->witness_program->get_legacy_address;
}

sub get_segwit_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	return encode_segwit($self->network->segwit_hrp, $self->witness_program->run->stack_serialized);
}

sub get_address
{
	my ($self) = @_;
	my $address = $self->get_raw_address;

	return undef
		unless $self->has_type && defined $address;

	if ($self->is_native_segwit) {

		# network field is not required, lazy check for completeness
		Bitcoin::Crypto::Exception::NetworkConfig->raise(
			'this network does not support segregated witness'
		) unless $self->network->supports_segwit;

		my $version = pack 'C',
			$self->is_taproot
			? TAPROOT_WITNESS_VERSION
			: SEGWIT_WITNESS_VERSION;

		return encode_segwit($self->network->segwit_hrp, $version . $address);
	}
	elsif ($self->type eq 'P2PKH') {
		return encode_base58check($self->network->p2pkh_byte . $address);
	}
	elsif ($self->type eq 'P2SH') {
		return encode_base58check($self->network->p2sh_byte . $address);
	}
	elsif ($self->type eq 'NULLDATA') {
		return qq("$address");
	}
}

sub has_type
{
	my ($self) = @_;

	return defined $self->type;
}

sub is_empty
{
	my ($self) = @_;

	return length $self->_serialized == 0;
}

sub dump
{
	my ($self) = @_;

	my $ops = $self->operations;
	my $num = @$ops;

	return 'Empty script' unless $num;

	my $type = $self->type // 'Custom';
	my $errors = $self->has_errors ? ' (with errors)' : '';

	my @result;
	CORE::push @result, "$type script$errors, $num ops:";
	foreach my $op (@$ops) {
		CORE::push @result, '  ' . $op->[0]->name . ' (' . (to_format [hex => $op->[1]]) . ')';
	}

	return join "\n", @result;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Script - Bitcoin Script instance

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script;

	my $script = Bitcoin::Crypto::Script->from_standard(
		[P2WPKH => $my_segwit_address]
	);

	# getting serialized script
	my $serialized = $script->to_serialized();

	# getting P2WSH address from script
	my $sh_address = $script->get_segwit_address();

	# getting back the address encoded in P2WPKH script
	my $address = $script->get_address();


=head1 DESCRIPTION

This class allows you to create Perl representation of a Bitcoin script.

You can use a script object to:

=over

=item * create a script from opcodes

=item * serialize a script into byte string

=item * deserialize a script into a sequence of opcodes

=item * create legacy (p2sh), compat (p2sh(p2wsh)) and segwit (p2wsh) addresses

=item * execute the script

=back

Note that taproot addresses (p2tr) with script spend paths are created using
L<Bitcoin::Crypto::Key::Public>.

=head1 INTERFACE

=head2 Attributes

=head3 type

Contains the type of the script, if the script is standard and the type is
known. Otherwise, contains C<undef>.

I<predicate>: B<has_type>

=head3 network

Instance of L<Bitcoin::Crypto::Network> - current network for this key. Can be
coerced from network id. Default: current default network.

I<writer:> C<set_network>

=head2 Methods

=head3 new

	$script_object = $class->new()

A constructor. Returns a new empty script instance.

See L</from_serialized> if you want to import a serialized script instead.

=head3 opcode_class

	$class_name = $class->opcode_class()
	$class->opcode_class->get_opcode_by_name($opname)

Returns the name of the class used to get the proper opcodes.

=head3 add_operation, add

	$script_object = $object->add_operation($opcode)

Adds a new opcode at the end of a script. Returns the object instance for chaining.

C<add> is a shorter alias for C<add_operation>.

Throws an exception for unknown opcodes.

=head3 add_raw

	$script_object = $object->add_raw($bytes)

Adds C<$bytes> at the end of the script without processing them at all.

Returns the object instance for chaining.

=head3 push_bytes, push

	$script_object = $object->push_bytes($bytes)

Pushes C<$bytes> to the execution stack at the end of a script, using a minimal push opcode.

C<push> is a shorter alias for C<push_bytes>.

For example, running C<< $script->push_bytes("\x03") >> will have the same
effect as C<< $script->add_operation('OP_3') >>.

Throws an exception for data exceeding a 4 byte number in length.

Note that no data longer than 520 bytes can be pushed onto the stack in one
operation, but this method will not check for that.

Returns the object instance for chaining.

=head3 push_number

	$script_object = $object->push_number($int)

Same as C<push_bytes>, but C<$int> will be treated as a script number and turned
into a byte representation first. Useful if you have a non-trivial number that
needs to be pushed onto a stack.

=head3 to_serialized

	$bytestring = $object->to_serialized()

Returns a serialized script as byte string.

=head3 from_serialized

	$script = Bitcoin::Crypto::Script->from_serialized($bytestring)

Creates a new script instance from a bytestring.

=head3 from_standard

	$object = Bitcoin::Crypto::Script->from_standard([P2PKH => '1Ehr6cNDzPCx3wQRu1sMdXWViEi2MQnFzH'])
	$object = Bitcoin::Crypto::Script->from_standard([address => '1Ehr6cNDzPCx3wQRu1sMdXWViEi2MQnFzH'])

Creates a new object of standard type with given address. The address must be
of the currently default network. In case of C<NULLDATA>, C<P2MS> and C<P2PK>
there is no address, and the second argument must be custom data (C<NULLDATA>),
public key (C<P2PK>) or an array reference with number C<N> of signatures followed
by C<M> public keys (C<N> of C<M> C<P2MS>).

The first argument can also be specified as C<address> to enable auto-detection
of script type.

=head3 get_hash

	$bytestring = $object->get_hash()

Returns a serialized script parsed with C<HASH160> (C<RIPEMD160> of C<SHA256>).

=head3 get_legacy_address

	$address = $object->get_legacy_address()

Returns string containing Base58Check encoded script hash (C<P2SH> address)

=head3 get_compat_address

	$address = $object->get_compat_address()

Returns string containing Base58Check encoded script hash containing a witness
program for compatibility purposes (C<P2SH(P2WSH)> address)

=head3 get_segwit_address

	$address = $object->get_segwit_address()

Returns string containing Bech32 encoded witness program (C<P2WSH> address)

=head3 get_address

	$address = $object->get_address()

This method does not generate P2SH-type address, but instead returns the
address encoded in the script of standard type. For example, if the script is
of type C<P2WPKH>, then a bech32 segwit address will be returned. If the script
is not of standard type or the type does not use addresses, returns C<undef>.

Currently handles script of types C<P2PKH>, C<P2SH>, C<P2WPKH>, C<P2WSH>, C<P2TR>.

=head3 get_raw_address

	$raw_address = $object->get_raw_address()

Same as L</get_address>, but does not encode the address with base58 / bech32,
and does not add any network markers specific for this type of address. Can be
used to fetch the data encoded in a standard script type, for example output
xonly public key for C<P2TR>.

=head3 operations

	$ops_aref = $object->operations

Returns an array reference - An array of operations to be executed. Same as
L<Bitcoin::Crypto::Script::Runner/operations>, which is only filled after
starting the script.

	[
		[OP_XXX (Object), raw (String), ...],
		...
	]

The first element of each subarray is the L<Bitcoin::Crypto::Script::Opcode>
object. The second element is the raw opcode string, usually single byte. The
rest of elements are metadata and is dependant on the op type. This metadata is
used during script execution.

Note that operations are returned even for invalid scripts. See L</has_errors> and L</assert_valid>.

=head3 has_errors

	$bool = $object->has_errors()

Returns a true value if the script is syntax is invalid - has pushes past end
of the script, opcode errors like unclosed OP_IFs, or opcodes that make it
invalid on compilation like OP_VERIF.

Note that having errors may not be a good indicator whether the script is
correct, since it may be unconditionally valid due to OP_SUCCESS (in
tapscripts). Script can have errors and still be valid because of that. See
L</assert_valid>.

=head3 assert_valid

	$object->assert_valid

Checks if the script is valid - either it has no errors, or it is marked an
unconditionally valid. If the script is not valid, the first error will be
raised as exception. If the script is valid, returns nothing.

=head3 run

	$runner = $object->run(\@initial_stack)

Executes the script and returns L<Bitcoin::Crypto::Script::Runner> instance
after running the script.

This is a convenience method which constructs runner instance in the
background. This helper is only meant to run simple scripts.

=head3 is_native_segwit

	$boolean = $object->is_native_segwit

Returns true if the type of the script is either C<P2WPKH>, C<P2WSH> or C<P2TR>.

=head3 is_empty

	$boolean = $object->is_empty

Returns true if the script is completely empty (contains no opcodes).

=head3 is_pushes_only

	$boolean = $object->is_pushes_only

Returns true if the script contains only opcodes pushing to the stack.

=head3 dump

	$string = $object->dump

Returns a readable representation of the script

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Script::Runner>

=item L<Bitcoin::Crypto::Script::Opcode>

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

