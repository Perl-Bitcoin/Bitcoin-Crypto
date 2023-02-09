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

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Helpers qw(pad_hex carp_once);
use Bitcoin::Crypto::Util qw(hash160 hash256);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(ArrayRef Str Object ByteStr Any);
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Script::Runner;

use namespace::clean;

has field '_serialized' => (
	isa => Str,
	writer => 1,
	default => '',
);

with qw(Bitcoin::Crypto::Role::Network);

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
			my $size = unpack 'C', substr $serialized, 0, 1, '';

			push @$op, $data_push->($size);
		},
		OP_PUSHDATA2 => sub {
			my ($op) = @_;
			my $size = unpack 'v', substr $serialized, 0, 2, '';

			push @$op, $data_push->($size);
		},
		OP_PUSHDATA4 => sub {
			my ($op) = @_;
			my $size = unpack 'V', substr $serialized, 0, 4, '';

			push @$op, $data_push->($size);
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
			) if @{$context{op_if}} > 1;

			$context{op_else} = $op;

			push @{$context{op_if}}, $pos;
		},
		OP_ENDIF => sub {
			my ($op, $pos) = @_;

			Bitcoin::Crypto::Exception::ScriptSyntax->raise(
				'OP_ENDIF found but no previous OP_IF or OP_NOTIF'
			) if !$context{op_if};

			push @{$context{op_if}}, undef
				if @{$context{op_if}} == 1;
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
				my $to_push = [$opcode];

				if (exists $special_ops{$opcode->name}) {
					$special_ops{$opcode->name}->($to_push, $position);
				}

				push @ops, $to_push;
			}
			catch {
				my $err = $_;

				my $opcode_num = ord($this_byte);
				unless ($opcode_num > 0 && $opcode_num <= 75) {
					push @debug_ops, pack 'H*', $this_byte;
					die $err;
				}

				# NOTE: compiling this into PUSHDATA1 for now
				my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name('OP_PUSHDATA1');
				push @debug_ops, $opcode->name;

				push @ops, [$opcode, $data_push->($opcode_num)];
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
	Bitcoin::Crypto::Exception::ScriptPush->raise(
		'empty push_bytes data argument'
	) unless $len;

	if ($len == 1 && ord($bytes) <= 0x10) {
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

signature_for get_script => (
	method => Object,
	positional => [],
);

sub get_script
{
	my ($self) = @_;

	return $self->_serialized;
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
	carp_once "Bitcoin::Crypto::Script->get_script_hash is deprecated. Use Bitcoin::Crypto::Script->get_hash instead.";
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

signature_for from_serialized_hex => (
	method => Str,
	positional => [Str],
);

sub from_serialized_hex
{
	my ($class, $hex) = @_;

	return $class->from_serialized(pack 'H*', pad_hex $hex);
}

signature_for run => (
	method => Object,
	positional => [],
);

sub run
{
	my ($self) = @_;

	my $runner = Bitcoin::Crypto::Script::Runner->new;
	return $runner->execute($self)->stack;
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
		->push_bytes(sha256($self->get_script));

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

	return encode_segwit($self->network->segwit_hrp, join '', @{$self->witness_program->run});
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Script - Bitcoin script instances

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script;

	my $script = Bitcoin::Crypto::Script->new
		->add_operation('OP_1')
		->add_operation('OP_TRUE')
		->add_operation('OP_EQUAL');

	# getting serialized script
	my $serialized = $script->get_script();

	# getting address from script (p2wsh)
	my $address = $script->get_segwit_adress();

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

=head1 METHODS

=head2 new

	$script_object = $class->new()

A constructor. Returns a new empty script instance.

See L</from_serialized> if you want to import a serialized script instead.

=head2 operations

	$ops_aref = $object->operations;

Returns an array reference of operations contained in a script:

	[
		['OP_XXX', ...],
		...
	]

The first element of each subarray is the op name. The rest of elements are
metadata and is dependant on the op type. This metadata is used during script execution.

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

For example, running C<< $script->push_bytes("\x03") >> will have the same effect as C<< $script->add_operation('OP_3') >>.

Throws an exception for data exceeding a 4 byte number in length.

Note that no data longer than 520 bytes can be pushed onto the stack in one operation, but this method will not check for that.

Returns the object instance for chaining.

=head2 to_serialized

	$bytestring = $object->get_script()

Returns a serialized script as byte string.

=head2 from_serialized

	$script = Bitcoin::Crypto::Script->from_serialized($bytestring);

Creates a new script instance from a bytestring.

=head2 get_script

Same as L</to_serialized>.

=head2 get_hash

	$bytestring = $object->get_hash()

Returns a serialized script parsed with C<HASH160> (ripemd160 of sha256).

=head2 set_network

	$script_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in L<Bitcoin::Crypto::Network> package or an instance of this class.

Returns current object instance.

=head2 get_legacy_address

	$address = $object->get_legacy_address()

Returns string containing Base58Check encoded script hash (p2sh address)

=head2 get_compat_address

	$address = $object->get_compat_address()

Returns string containing Base58Check encoded script hash containing a witness program for compatibility purposes (p2sh(p2wsh) address)

=head2 get_segwit_address

	$address = $object->get_segwit_address()

Returns string containing Bech32 encoded witness program (p2wsh address)

=head2 run

	my $result_stack = $object->run;

Executes the script and returns the resulting script stack.

This is a convenience method which constructs runner instance in the
background. See L<Bitcoin::Crypto::Script::Runner> for details and advanced usage.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * ScriptOpcode - unknown opcode was specified

=item * ScriptPush - data pushed to the execution stack is invalid

=item * ScriptSyntax - script syntax is invalid

=item * ScriptRuntime - script runtime error

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Script::Runner>

=item L<Bitcoin::Crypto::Script::Opcode>

=item L<Bitcoin::Crypto::Network>

=back

=cut

