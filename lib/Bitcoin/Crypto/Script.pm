package Bitcoin::Crypto::Script;

use v5.10;
use strict;
use warnings;
use Moo;
use Crypt::Digest::SHA256 qw(sha256);
use Mooish::AttributeBuilder -standard;
use Try::Tiny;

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(hash160 hash256 verify_bytestring);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(ArrayRef Str);
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Script::Runner;

use namespace::clean;

has field '_serialized' => (
	isa => Str,
	writer => 1,
	default => '',
);

with qw(Bitcoin::Crypto::Role::Network);

sub operations
{
	my ($self) = @_;

	my $serialized = $self->_serialized;
	my @ops;

	my $data_push = sub {
		my ($size) = @_;

		Bitcoin::Crypto::Exception::ScriptSyntax(
			'not enough bytes of data in the script'
		) if length $serialized < $size;

		return substr $serialized, 0, $size, '';
	};

	my %special_ops = (
		OP_PUSHDATA1 => sub {
			my $size = unpack 'C', substr $serialized, 0, 1, '';

			return $data_push->($size);
		},
		OP_PUSHDATA2 => sub {
			my $size = unpack 'v', substr $serialized, 0, 2, '';

			return $data_push->($size);
		},
		OP_PUSHDATA4 => sub {
			my $size = unpack 'V', substr $serialized, 0, 4, '';

			return $data_push->($size);
		},
		# TODO: if, else, endif
	);

	while (length $serialized) {
		my $this_byte = substr $serialized, 0, 1, '';

		try {
			my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_code($this_byte);
			my @to_push = ($opcode);

			if (exists $special_ops{$opcode->name}) {
				push @to_push, $special_ops{$opcode->name}->();
			}

			push @ops, \@to_push;
		}
		catch {
			my $err = $_;

			my $opcode_num = ord($this_byte);
			unless ($opcode_num > 0 && $opcode_num <= 75) {
				die $err;
			}

			# NOTE: compiling this into PUSHDATA1 for now
			push @ops, [
				Bitcoin::Crypto::Script::Opcode->get_opcode_by_name('OP_PUSHDATA1'),
				$data_push->($opcode_num)
			];
		};
	}

	return \@ops;
}

sub add_raw
{
	my ($self, $bytes) = @_;
	verify_bytestring($bytes);

	$self->_set_serialized($self->_serialized . $bytes);
	return $self;
}

sub add_operation
{
	my ($self, $name) = @_;
	my $opcode = Bitcoin::Crypto::Script::Opcode->get_opcode_by_name($name);
	$self->add_raw($opcode->code);

	return $self;
}

sub push_bytes
{
	my ($self, $bytes) = @_;
	verify_bytestring($bytes);

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
	elsif (Bitcoin::Crypto::Config::is_32bit || $len < (1 << 32)) {
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

sub get_script
{
	my ($self) = @_;

	return $self->_serialized;
}

sub get_script_hash
{
	my ($self) = @_;
	return hash160($self->_serialized);
}

sub to_serialized
{
	my ($self) = @_;

	return $self->_serialized;
}

sub from_serialized
{
	my ($class, $bytes) = @_;

	return $class->new->add_raw($bytes);
}

sub run
{
	my ($self) = @_;

	my $runner = Bitcoin::Crypto::Script::Runner->new;
	return $runner->execute($self)->stack;
}

sub witness_program
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program
		->add_operation('OP_' . Bitcoin::Crypto::Config::witness_version)
		->push_bytes(sha256($self->get_script));

	return $program;
}

sub get_legacy_address
{
	my ($self) = @_;
	return encode_base58check($self->network->p2sh_byte . $self->get_script_hash);
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

	return encode_segwit($self->network->segwit_hrp, join '', @{$self->witness_program->run});
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Script - Bitcoin script representations

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

This class allows you to create a bitcoin script representations

You can use a script object to:

=over 2

=item * create a script from opcodes

=item * serialize script into byte string

=item * create legacy (p2sh), compat (p2sh(p2wsh)) and segwit (p2wsh) adresses

=back

=head1 METHODS

=head2 new

	$script_object = $class->new()

A constructor. Returns new script instance.

=head2 add_operation

	$script_object = $object->add_operation($opcode)

Adds a new opcode at the end of a script. Returns the object instance for chaining.

Throws an exception for unknown opcodes.

=head2 add_raw

	$script_object = $object->add_raw($bytes)

Adds C<$bytes> at the end of a script.
Can be used to import serialized scripts.

Returns the object instance for chaining.

=head2 push_bytes

	$script_object = $object->push_bytes($bytes)

Pushes C<$bytes> to the execution stack at the end of a script, using a minimal push opcode.

For example, running C<< $script->push_bytes("\x03") >> will have the same effect as C<< $script->add_operation('OP_3') >>.

Throws an exception for data exceeding a 4 byte number in length.

Note that no data longer than 520 bytes can be pushed onto the stack in one operation, but this method will not check for that.

Returns the object instance for chaining.

=head2 get_script

	$bytestring = $object->get_script()

Returns a serialized script as byte string.

=head2 get_script_hash

	$bytestring = $object->get_script_hash()

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

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * ScriptOpcode - unknown opcode was specified

=item * ScriptPush - data pushed to the execution stack is invalid

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Network>

=back

=cut

