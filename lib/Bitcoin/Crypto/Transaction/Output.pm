package Bitcoin::Crypto::Transaction::Output;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Int BitcoinScript InstanceOf Object Str ByteStr PositiveOrZeroInt ScalarRef);
use Bitcoin::Crypto::Helpers qw(pack_varint unpack_varint ensure_length);    # loads BigInt
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Exception;

use namespace::clean;

has param 'value' => (
	writer => 1,
	coerce => (InstanceOf ['Math::BigInt'])
		->where(q{$_ >= 0})
		->plus_coercions(Int | Str, q{ Math::BigInt->new($_) }),
);

has param 'locking_script' => (
	coerce => BitcoinScript,
	writer => 1,
);

with qw(
	Bitcoin::Crypto::Role::ShallowClone
);

signature_for is_standard => (
	method => Object,
	positional => [],
);

sub is_standard
{
	my ($self) = @_;

	return $self->locking_script->has_type;
}

signature_for set_max_value => (
	method => Object,
	positional => [],
);

sub set_max_value
{
	my ($self) = @_;

	$self->set_value('0xffffffffffffffff');
	return $self;
}

signature_for value_serialized => (
	method => Object,
	positional => [],
);

sub value_serialized
{
	my ($self) = @_;

	# NOTE: little endian
	my $value = $self->value->as_bytes;
	return scalar reverse ensure_length($value, 8);
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	# output should be serialized as follows:
	# - value, 8 bytes
	# - locking script length, 1-9 bytes
	# - locking script
	my $serialized = '';

	$serialized .= $self->value_serialized;

	my $script = $self->locking_script->to_serialized;
	$serialized .= pack_varint(length $script);
	$serialized .= $script;

	return $serialized;
}

signature_for from_serialized => (
	method => Str,
	head => [ByteStr],
	named => [
		pos => ScalarRef [PositiveOrZeroInt],
		{optional => !!1},
	],
	bless => !!0,
);

sub from_serialized
{
	my ($class, $serialized, $args) = @_;
	my $partial = !!$args->{pos};
	my $pos = $partial ? ${$args->{pos}} : 0;

	my $value = reverse substr $serialized, $pos, 8;
	$pos += 8;

	my ($script_size_len, $script_size) = unpack_varint $serialized, $pos;
	$pos += $script_size_len;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized input script data is corrupted'
	) if $pos + $script_size > length $serialized;

	my $script = substr $serialized, $pos, $script_size;
	$pos += $script_size;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized output data is corrupted'
	) if !$partial && $pos != length $serialized;

	${$args->{pos}} = $pos
		if $partial;

	return $class->new(
		value => Math::BigInt->from_bytes($value),
		locking_script => $script,
	);
}

signature_for dump => (
	method => Object,
	positional => [],
);

sub dump
{
	my ($self) = @_;

	my $type = $self->locking_script->type // 'Custom';
	my $address = $self->locking_script->get_address // '';
	$address = " to $address" if $address;

	my @result;
	push @result, "$type Output$address";
	push @result, 'value: ' . $self->value;
	push @result, 'locking script: ' . to_format [hex => $self->locking_script->to_serialized];

	return join "\n", @result;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Transaction::Output - Bitcoin transaction output instance

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_transaction);

	my $tx = btc_transaction->new;

	$tx->add_output(
		value => 1234,
		locking_script => [P2WPKH => $my_address],
	);

	print $tx->outputs->[0]->dump;


=head1 DESCRIPTION

This is an output instance implementation used in transactions. It is rarely
interacted with directly.

=head1 INTERFACE

=head2 Attributes

=head3 value

Non-negative integer value of the output in the smallest unit (satoshi). It is
an instance of L<Math::BigInt> with type coercions from integers and strings.
Required.

I<Available in the constructor>.

I<writer>: C<set_value>

=head3 locking_script

An instance of the script used to lock the coins. Required.

Can be constructed from a standard script by passing an array reference with
script type and an address.

I<Available in the constructor>.

I<writer>: C<set_locking_script>

=head2 Methods

=head3 new

	$block = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 is_standard

	$boolean = $object->is_standard()

Returns true if L</locking_script> is a standard script type.

=head3 set_max_value

	$object = $object->set_max_value()

Sets the max possible value for this output, as required by digests. Mostly
used internally.

=head3 value_serialized

	$bytestring = $object->value_serialized()

Returns the bytesting of serialized value ready to be included in a serialized
transaction or digest. Mostly used internally.

=head3 to_serialized

	$bytestring = $object->to_serialized()

Returns the serialized output data to be included into a serialized transaction.

=head3 from_serialized

	$object = $class->from_serialized($bytestring, %params)

Creates an object instance from serialized data.

C<%params> can be any of:

=over

=item * C<pos>

Position for partial string decoding. Optional. If passed, must be a scalar
reference to an integer value.

This integer will mark the starting position of C<$bytestring> from which to
start decoding. It will be set to the next byte after end of output stream.

=back

=head3 dump

	$text = $object->dump()

Returns a readable description of the output.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * Transaction - general error with transaction

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=item L<Bitcoin::Crypto::Transaction::UTXO>

=back

=cut

