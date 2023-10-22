package Bitcoin::Crypto::Script;

use v5.10;
use strict;
use warnings;
use Moo;
use Crypt::Digest::SHA256 qw(sha256);
use Mooish::AttributeBuilder -standard;
use Try::Tiny;
use Scalar::Util qw(blessed);
use Type::Params -sigs;
use Carp qw(carp);

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit decode_segwit get_hrp);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Util qw(hash160 hash256 get_address_type);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Maybe ArrayRef HashRef Str Object ByteStr Any ScriptType ScriptDesc);
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Script::Common;
use Bitcoin::Crypto::Script::Recognition;

use namespace::clean;

has field '_serialized' => (
	isa => Str,
	writer => 1,
	default => '',
);

has field 'type' => (
	isa => Maybe [ScriptType],
	lazy => 1,
);

has field '_address' => (
	isa => Maybe [ByteStr],
	lazy => 1,
);

with qw(Bitcoin::Crypto::Role::Network);

sub _build_type
{
	my ($self) = @_;

	my $rec = Bitcoin::Crypto::Script::Recognition->new(script => $self);
	return $rec->get_type;
}

sub _build_address
{
	my ($self) = @_;

	my $rec = Bitcoin::Crypto::Script::Recognition->new(script => $self);
	return $rec->get_address;
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

signature_for operations => (
	method => Object,
	positional => [],
);

sub operations
{
	my ($self) = @_;

	my $serialized = $self->_serialized;
	my @ops;

	my $data_push = sub {
		my ($size) = @_;

		Bitcoin::Crypto::Exception::ScriptSyntax->raise(
			'not enough bytes of data in the script'
		) if length $serialized < $size;

		return substr $serialized, 0, $size, '';
	};

	my %context = (
		op_if => undef,
		op_else => undef,
		previous_context => undef,
	);

	my %special_ops = (
		OP_PUSHDATA1 => sub {
			my ($op) = @_;
			my $raw_size = substr $serialized, 0, 1, '';
			my $size = unpack 'C', $raw_size;

			push @$op, $data_push->($size);
			$op->[1] .= $raw_size . $op->[2];
		},
		OP_PUSHDATA2 => sub {
			my ($op) = @_;
			my $raw_size = substr $serialized, 0, 2, '';
			my $size = unpack 'v', $raw_size;

			push @$op, $data_push->($size);
			$op->[1] .= $raw_size . $op->[2];
		},
		OP_PUSHDATA4 => sub {
			my ($op) = @_;
			my $raw_size = substr $serialized, 0, 4, '';
			my $size = unpack 'V', $raw_size;

			push @$op, $data_push->($size);
			$op->[1] .= $raw_size . $op->[2];
		},
		OP_IF => sub {
			my ($op) = @_;

			if ($context{op_if}) {
				%context = (
					previous_context => {%context},
				);
			}
			$context{op_if} = $op;
		},
		OP_ELSE => sub {
			my ($op, $pos) = @_;

			Bitcoin::Crypto::Exception::ScriptSyntax->raise(
				'OP_ELSE found but no previous OP_IF or OP_NOTIF'
			) if !$context{op_if};

			Bitcoin::Crypto::Exception::ScriptSyntax->raise(
				'multiple OP_ELSE for a single OP_IF'
			) if @{$context{op_if}} > 2;

			$context{op_else} = $op;

			push @{$context{op_if}}, $pos;
		},
		OP_ENDIF => sub {
			my ($op, $pos) = @_;

			Bitcoin::Crypto::Exception::ScriptSyntax->raise(
				'OP_ENDIF found but no previous OP_IF or OP_NOTIF'
			) if !$context{op_if};

			push @{$context{op_if}}, undef
				if @{$context{op_if}} == 2;
			push @{$context{op_if}}, $pos;

			if ($context{op_else}) {
				push @{$context{op_else}}, $pos;
			}

			if ($context{previous_context}) {
				%context = %{$context{previous_context}};
			}
			else {
				%context = ();
			}
		},
	);

	$special_ops{OP_NOTIF} = $special_ops{OP_IF};
	my @debug_ops;
	my $position = 0;

	try {
		while (length $serialized) {
			my $this_byte = substr $serialized, 0, 1, '';

			try {
				my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_code($this_byte);
				push @debug_ops, $opcode->name;
				my $to_push = [$opcode, $this_byte];

				if (exists $special_ops{$opcode->name}) {
					$special_ops{$opcode->name}->($to_push, $position);
				}

				push @ops, $to_push;
			}
			catch {
				my $err = $_;

				my $opcode_num = ord($this_byte);
				unless ($opcode_num > 0 && $opcode_num <= 75) {
					push @debug_ops, unpack 'H*', $this_byte;
					die $err;
				}

				# NOTE: compiling standard data push into PUSHDATA1 for now
				my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name('OP_PUSHDATA1');
				push @debug_ops, $opcode->name;

				my $raw_data = $data_push->($opcode_num);
				push @ops, [$opcode, $this_byte . $raw_data, $raw_data];
			};

			$position += 1;
		}

		Bitcoin::Crypto::Exception::ScriptSyntax->raise(
			'some OP_IFs were not closed'
		) if $context{op_if};
	}
	catch {
		my $ex = $_;
		if (blessed $ex && $ex->isa('Bitcoin::Crypto::Exception::ScriptSyntax')) {
			$ex->set_script(\@debug_ops);
			$ex->set_error_position($position);
		}

		die $ex;
	};

	return \@ops;
}

signature_for is_pushes_only => (
	method => Object,
	positional => [],
);

sub is_pushes_only
{
	my ($self) = @_;

	foreach my $op (@{$self->operations}) {
		return !!0 unless $op->[0]->pushes;
	}

	return !!1;
}

signature_for add_raw => (
	method => Object,
	positional => [ByteStr],
);

sub add_raw
{
	my ($self, $bytes) = @_;

	$self->_set_serialized($self->_serialized . $bytes);
	return $self;
}

signature_for add_operation => (
	method => Object,
	positional => [Str],
);

sub add_operation
{
	my ($self, $name) = @_;

	my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($name);
	$self->add_raw($opcode->code);

	return $self;
}

sub add
{
	goto \&add_operation;
}

signature_for push_bytes => (
	method => Object,
	positional => [ByteStr],
);

sub push_bytes
{
	my ($self, $bytes) = @_;

	my $len = length $bytes;

	if ($len == 0) {
		$self->add_operation('OP_0');
	}
	elsif ($len == 1 && ord($bytes) <= 0x10) {
		$self->add_operation('OP_' . ord($bytes));
	}
	elsif ($len <= 75) {
		$self
			->add_raw(pack 'C', $len)
			->add_raw($bytes);
	}
	elsif ($len < (1 << 8)) {
		$self
			->add_operation('OP_PUSHDATA1')
			->add_raw(pack 'C', $len)
			->add_raw($bytes);
	}
	elsif ($len < (1 << 16)) {
		$self
			->add_operation('OP_PUSHDATA2')
			->add_raw(pack 'v', $len)
			->add_raw($bytes);
	}
	elsif (Bitcoin::Crypto::Constants::is_32bit || $len < (1 << 32)) {
		$self
			->add_operation('OP_PUSHDATA4')
			->add_raw(pack 'V', $len)
			->add_raw($bytes);
	}
	else {
		Bitcoin::Crypto::Exception::ScriptPush->raise(
			'too much data to push onto stack in one operation'
		);
	}

	return $self;
}

sub push
{
	goto \&push_bytes;
}

# this can only detect native segwit in this context, as P2SH outputs are
# indistinguishable from any other P2SH
signature_for is_native_segwit => (
	method => Object,
	positional => [],
);

sub is_native_segwit
{
	my ($self) = @_;
	my @segwit_types = qw(P2WPKH P2WSH);

	my $script_type = $self->type // '';

	return 0 != grep { $script_type eq $_ } @segwit_types;
}

sub get_script
{
	my ($self) = @_;

	carp "Bitcoin::Crypto::Script->get_script is deprecated. Use Bitcoin::Crypto::Script->to_serialized instead.";
	return $self->to_serialized;
}

signature_for get_hash => (
	method => Object,
	positional => [],
);

sub get_hash
{
	my ($self) = @_;
	return hash160($self->_serialized);
}

sub get_script_hash
{
	carp "Bitcoin::Crypto::Script->get_script_hash is deprecated. Use Bitcoin::Crypto::Script->get_hash instead.";
	goto \&get_hash;
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	return $self->_serialized;
}

signature_for from_serialized => (
	method => Str,
	positional => [Any],

	# no need to validate ByteStr, as it will be passed to add_raw
);

sub from_serialized
{
	my ($class, $bytes) = @_;

	return $class->new->add_raw($bytes);
}

signature_for from_standard => (
	method => Str,
	positional => [ScriptDesc, {slurpy => 1}],
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
	method => Object,
	positional => [ArrayRef [ByteStr], {default => []}],
);

sub run
{
	my ($self, $initial_stack) = @_;

	my $runner = Bitcoin::Crypto::Script::Runner->new();
	return $runner->execute($self, $initial_stack);
}

signature_for witness_program => (
	method => Object,
	positional => [],
);

sub witness_program
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program
		->add_operation('OP_' . Bitcoin::Crypto::Constants::segwit_witness_version)
		->push_bytes(sha256($self->to_serialized));

	return $program;
}

signature_for get_legacy_address => (
	method => Object,
	positional => [],
);

sub get_legacy_address
{
	my ($self) = @_;
	return encode_base58check($self->network->p2sh_byte . $self->get_hash);
}

signature_for get_compat_address => (
	method => Object,
	positional => [],
);

sub get_compat_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	return $self->witness_program->get_legacy_address;
}

signature_for get_segwit_address => (
	method => Object,
	positional => [],
);

sub get_segwit_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'this network does not support segregated witness'
	) unless $self->network->supports_segwit;

	return encode_segwit($self->network->segwit_hrp, $self->witness_program->run->stack_serialized);
}

signature_for get_address => (
	method => Object,
	positional => [],
);

sub get_address
{
	my ($self) = @_;
	my $address = $self->_address;

	return undef
		unless $self->has_type && defined $address;

	my $segwit = sub {
		my ($version, $address) = @_;

		# network field is not required, lazy check for completeness
		Bitcoin::Crypto::Exception::NetworkConfig->raise(
			'this network does not support segregated witness'
		) unless $self->network->supports_segwit;

		return encode_segwit($self->network->segwit_hrp, $version . $address);
	};

	if ($self->is_native_segwit) {
		my $version = pack 'C', Bitcoin::Crypto::Constants::segwit_witness_version;
		return $segwit->($version, $address);
	}
	elsif ($self->type eq 'P2TR') {
		my $version = pack 'C', Bitcoin::Crypto::Constants::taproot_witness_version;
		return $segwit->($version, $address);
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

signature_for has_type => (
	method => Object,
	positional => [],
);

sub has_type
{
	my ($self) = @_;

	return defined $self->type;
}

signature_for is_empty => (
	method => Object,
	positional => [],
);

sub is_empty
{
	my ($self) = @_;

	return length $self->_serialized == 0;
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
	my $sh_address = $script->get_segwit_adress();

	# getting back the address encoded in P2WPKH script
	my $address = $script->get_address();


=head1 DESCRIPTION

This class allows you to create Perl representation of a Bitcoin script.

You can use a script object to:

=over 2

=item * create a script from opcodes

=item * serialize a script into byte string

=item * deserialize a script into a sequence of opcodes

=item * create legacy (p2sh), compat (p2sh(p2wsh)) and segwit (p2wsh) adresses

=item * execute the script

=back

=head1 ATTRIBUTES

=head2 type

Contains the type of the script, if the script is standard and the type is
known. Otherwise, contains C<undef>.

I<predicate>: C<has_type>

=head1 METHODS

=head2 new

	$script_object = $class->new()

A constructor. Returns a new empty script instance.

See L</from_serialized> if you want to import a serialized script instead.

=head2 operations

	$ops_aref = $object->operations

Returns an array reference of operations contained in a script:

	[
		[OP_XXX (Object), raw (String), ...],
		...
	]

The first element of each subarray is the L<Bitcoin::Crypto::Script::Opcode>
object. The second element is the raw opcode string, usually single byte. The
rest of elements are metadata and is dependant on the op type. This metadata is
used during script execution.

=head2 add_operation, add

	$script_object = $object->add_operation($opcode)

Adds a new opcode at the end of a script. Returns the object instance for chaining.

C<add> is a shorter alias for C<add_operation>.

Throws an exception for unknown opcodes.

=head2 add_raw

	$script_object = $object->add_raw($bytes)

Adds C<$bytes> at the end of the script without processing them at all.

Returns the object instance for chaining.

=head2 push_bytes, push

	$script_object = $object->push_bytes($bytes)

Pushes C<$bytes> to the execution stack at the end of a script, using a minimal push opcode.

C<push> is a shorter alias for C<push_bytes>.

For example, running C<< $script->push_bytes("\x03") >> will have the same
effect as C<< $script->add_operation('OP_3') >>.

Throws an exception for data exceeding a 4 byte number in length.

Note that no data longer than 520 bytes can be pushed onto the stack in one
operation, but this method will not check for that.

Returns the object instance for chaining.

=head2 to_serialized

	$bytestring = $object->to_serialized()

Returns a serialized script as byte string.

=head2 from_serialized

	$script = Bitcoin::Crypto::Script->from_serialized($bytestring);

Creates a new script instance from a bytestring.

=head2 from_standard

	$object = Bitcoin::Crypto::Script->from_standard([P2PKH => '1Ehr6cNDzPCx3wQRu1sMdXWViEi2MQnFzH'])
	$object = Bitcoin::Crypto::Script->from_standard([address => '1Ehr6cNDzPCx3wQRu1sMdXWViEi2MQnFzH'])

Creates a new object of standard type with given address. The address must be
of the currently default network. In case of C<NULLDATA>, C<P2MS> and C<P2PK>
there is no address, and the second argument must be custom data (C<NULLDATA>),
public key (C<P2PK>) or an array reference with number N of signatures followed
by M public keys (N of M C<P2MS>).

The first argument can also be specified as C<address> to enable auto-detection
of script type.

=head2 get_hash

	$bytestring = $object->get_hash()

Returns a serialized script parsed with C<HASH160> (ripemd160 of sha256).

=head2 set_network

	$script_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in
L<Bitcoin::Crypto::Network> package or an instance of this class.

Returns current object instance.

=head2 get_legacy_address

	$address = $object->get_legacy_address()

Returns string containing Base58Check encoded script hash (P2SH address)

=head2 get_compat_address

	$address = $object->get_compat_address()

Returns string containing Base58Check encoded script hash containing a witness
program for compatibility purposes (P2SH(P2WSH) address)

=head2 get_segwit_address

	$address = $object->get_segwit_address()

Returns string containing Bech32 encoded witness program (P2WSH address)

=head2 get_address

	$address = $object->get_address()

This method does not return P2SH address, but instead the address encoded in
the script of standard type. For example, if the script is of type C<P2WPKH>,
then the contained alegacy address will be returned. If the script is not of
standard type or the type does not contain an address, returns C<undef>.

Currently handles script of types C<P2PKH>, C<P2SH>, C<P2WPKH>, C<P2WSH>.

=head2 run

	$runner = $object->run(\@initial_stack)

Executes the script and returns L<Bitcoin::Crypto::Script::Runner> instance
after running the script.

This is a convenience method which constructs runner instance in the
background. This helper is only meant to run simple scripts.

=head2 is_native_segwit

	$boolean = $object->is_native_segwit

Returns true if the type of the script is either C<P2WPKH> or C<P2WSH>.

=head2 is_empty

	$boolean = $object->is_empty

Returns true if the script is completely empty (contains no opcodes).

=head2 is_pushes_only

	$boolean = $object->is_pushes_only

Returns true if the script contains only opcodes pushing to the stack.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * ScriptOpcode - unknown opcode was specified

=item * ScriptPush - data pushed to the execution stack is invalid

=item * ScriptType - invalid standard script type name specified

=item * ScriptSyntax - script syntax is invalid

=item * ScriptRuntime - script runtime error

=item * SegwitProgram - Segregated witness address error

=item * NetworkConfig - incomplete or corrupted network configuration

=item * NetworkCheck - address does not belong to the configured network

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Script::Runner>

=item L<Bitcoin::Crypto::Script::Opcode>

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

