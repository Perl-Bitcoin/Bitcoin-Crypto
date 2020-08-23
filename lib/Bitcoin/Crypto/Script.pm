package Bitcoin::Crypto::Script;

use v5.10; use warnings;
use Moo;
use Types::Standard qw(ArrayRef Str);
use Crypt::Digest::SHA256 qw(sha256);

use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(hash160 hash256);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::ScriptEngine qw(get_opcode);
use Bitcoin::Crypto;

sub witness_script
{
	my ($self) = @_;

	my $script = $self
		->new(network => $self->network)
		->add_operation("OP_" . $config{witness_version})
		->push_bytes(sha256($self->get_script));

	return $script;
}

use namespace::clean;
our $VERSION = Bitcoin::Crypto->VERSION;

with "Bitcoin::Crypto::Role::Network";

has "operations" => (
	is => "rw",
	isa => ArrayRef [Str],
	default => sub { [] },
);

sub add_raw
{
	my ($self, $bytes) = @_;
	push @{$self->operations}, split //, $bytes;
	return $self;
}

sub add_operation
{
	my ($self, $op_code) = @_;
	my $val = get_opcode($op_code);
	$self->add_raw($val->{code});
	return $self;
}

sub push_number
{
	my ($self, $number) = @_;
	Bitcoin::Crypto::Exception::ScriptPush->raise(
		"not an integer number"
	) unless $number =~ /\A-?[0-9]+\z/;

	return $self->push_bytes(Bitcoin::Crypto::ScriptEngine::to_script_number($number));
}

sub push_bytes
{
	my ($self, $bytes) = @_;
	my $len = length $bytes;
	Bitcoin::Crypto::Exception::ScriptPush->raise(
		"empty data variable"
	) unless $len;

	if ($bytes =~ /[\x00-\x10]/ && $len == 1) {
		my $num = unpack "C", $bytes;
		$self->add_operation("OP_$num");
	}
	else {
		use bigint;
		if ($len <= 75) {
			$self->add_operation($len);
		}
		elsif ($len < (2 << 7)) {
			$self->add_operation("OP_PUSHDATA1")
				->add_raw(pack "C", $len);
		}
		elsif ($len < (2 << 15)) {
			$self->add_operation("OP_PUSHDATA2")
				->add_raw(pack "S", $len);
		}
		elsif ($len < (2 << 31)) {
			$self->add_operation("OP_PUSHDATA4")
				->add_raw(pack "L", $len);
		}
		else {
			Bitcoin::Crypto::Exception::ScriptPush->raise(
				"too much data to push onto stack in one operation"
			);
		}
		$self->add_raw($bytes);
	}
	return $self;
}

sub get_script
{
	my ($self) = @_;
	return join "", @{$self->operations};
}

sub get_script_hash
{
	my ($self) = @_;
	return hash160($self->get_script);
}

sub witness_program
{
	my ($self) = @_;

	return join "", @{witness_script($self)->execute};
}

sub get_legacy_address
{
	my ($self) = @_;
	return encode_base58check($self->network->p2sh_byte . $self->get_script_hash);
}

sub get_compat_address
{
	my ($self) = @_;

	return witness_script($self)->get_legacy_address;
}

sub get_segwit_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"no segwit_hrp found in network configuration"
	) unless defined $self->network->segwit_hrp;

	return encode_segwit($self->network->segwit_hrp, $self->witness_program);
}

sub execute
{
	my ($self, $debug) = @_;

	return $debug
		? Bitcoin::Crypto::ScriptEngine::debug_script($self->get_script)
		: Bitcoin::Crypto::ScriptEngine::execute_script($self->get_script);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Script - class for Bitcoin script representations

=head1 SYNOPSIS

	use Bitcoin::Crypto::Script;

	my $script = Bitcoin::Crypto::Script->new
		->add_operation("OP_1")
		->add_operation("OP_TRUE")
		->add_operation("OP_EQUAL");

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

=item * (work in progress) run script and get resulting stack

=back

=head1 METHODS

=head2 new

	sig: new($class, $data)

This works exactly the same as from_bytes

=head2 add_operation

	sig: add_operation($self, $opcode)

Adds a new opcode at the end of a script. Returns $self for chaining.
Throws an exception for unknown opcodes.

=head2 add_raw

	sig: add_raw($self, $bytes)

Adds $bytes at the end of a script.
Useful when you need a value in a script that shouldn't be pushed to the execution stack, like the first four bytes after PUSHDATA4.
Returns $self for chaining.

=head2 push_bytes

	sig: push_bytes($self, $bytes)

Pushes $bytes to the execution stack at the end of a script, using a minimal push opcode.
For example, running C<$script->push_bytes("\x03")> will have the same effect as C<$script->add_operation("OP_3")>.
Throws an exception for data exceeding a 4 byte number in length.
Returns $self for chaining.

=head2 get_script

	sig: get_script($self)

Returns a serialized script as byte string.

=head2 get_script_hash

	sig: get_script_hash($self)

Returns a serialized script parsed with HASH160 (ripemd160 of sha256).

=head2 set_network

	sig: set_network($self, $val)

Change key's network state to $val. It can be either network name present in Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 get_legacy_address

	sig: get_legacy_address($self)

Returns string containing Base58Check encoded script hash (p2sh address)

=head2 get_compat_address

	sig: get_compat_address($self)

Returns string containing Base58Check encoded script hash containing a witness program for compatibility purposes (p2sh(p2wsh) address)

=head2 get_segwit_address

	sig: get_segwit_address($self)

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

=item L<Bitcoin::Crypto::PrivateKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut
