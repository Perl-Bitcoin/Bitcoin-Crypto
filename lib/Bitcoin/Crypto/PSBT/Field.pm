package Bitcoin::Crypto::PSBT::Field;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types
	qw(Object Maybe Defined ByteStr Str InstanceOf PSBTFieldType PSBTMapType ScalarRef PositiveOrZeroInt);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::PSBT::FieldType;
use Bitcoin::Crypto::Util qw(to_format pack_compactsize unpack_compactsize);

use namespace::clean;

has field 'map' => (
	isa => InstanceOf ['Bitcoin::Crypto::PSBT::Map'],
	writer => -hidden,
	weak_ref => 1,
);

has param 'type' => (
	coerce => PSBTFieldType,
);

has param 'raw_key' => (
	coerce => Maybe [ByteStr],
	writer => -hidden,
	default => undef,
);

has param 'raw_value' => (
	coerce => ByteStr,
	writer => 1,
	default => '',
);

sub BUILD
{
	my ($self, $args) = @_;

	if (defined $self->raw_key && !$self->type->has_key_data) {
		Bitcoin::Crypto::Exception::PSBT->raise(
			'Field ' . $self->type->name . ' does not define key data'
		) if length $self->raw_key;

		$self->_set_raw_key(undef);
	}

	if (exists $args->{value}) {
		$self->set_value($args->{value});
	}

	if (exists $args->{key}) {
		$self->set_key($args->{key});
	}

}

signature_for validate => (
	method => Object,
	positional => []
);

sub validate
{
	my ($self) = @_;

	# at the very least, try deserializing value and key. If there is a
	# dedicated validator, run that as well with these values
	Bitcoin::Crypto::Exception::PSBT->trap_into(
		sub {
			my @args = ($self->value);
			if ($self->type->has_key_data) {
				unshift @args, $self->key;
			}

			$self->type->validator->(@args)
				if $self->type->has_validator;
		},
		'validation failed for type ' . $self->type->name
	);

	return $self;
}

signature_for key => (
	method => Object,
	positional => []
);

sub key
{
	my ($self) = @_;

	return $self->type->key_deserializer->($self->raw_key);
}

signature_for set_raw_key => (
	method => Object,
	positional => [Defined]
);

sub set_raw_key
{
	my ($self, $key) = @_;

	Bitcoin::Crypto::Exception::PSBT->raise(
		'Field ' . $self->type->name . ' does not define key data'
	) if !$self->type->has_key_data;

	$self->_set_raw_key($key);
	$self->map->_check_integrity($self)
		if $self->map;

	return;
}

signature_for set_key => (
	method => Object,
	positional => [Defined]
);

sub set_key
{
	my ($self, $key) = @_;

	$self->set_raw_key($self->type->key_serializer->($key));
	return;
}

signature_for value => (
	method => Object,
	positional => []
);

sub value
{
	my ($self) = @_;

	return $self->type->deserializer->($self->raw_value);
}

signature_for set_value => (
	method => Object,
	positional => [Defined]
);

sub set_value
{
	my ($self, $value) = @_;

	$self->set_raw_value($self->type->serializer->($value));
	return;
}

signature_for set_map => (
	method => Object,
	positional => [Defined],
);

sub set_map
{
	my ($self, $map) = @_;

	$self->validate;
	$self->_set_map($map);
	$map->_check_integrity($self);
	return;
}

signature_for serialized_key => (
	method => Object,
	positional => [],
);

sub serialized_key
{
	my ($self) = @_;

	return pack_compactsize($self->type->code) . ($self->raw_key // '');
}

signature_for from_serialized => (
	method => Str,
	head => [ByteStr],
	named => [
		map_type => PSBTMapType,
		pos => Maybe [ScalarRef [PositiveOrZeroInt]],
		{default => undef},
	],
	bless => !!0,
);

sub from_serialized
{
	my ($class, $serialized, $args) = @_;
	my $partial = !!$args->{pos};
	my $pos = $partial ? ${$args->{pos}} : 0;

	Bitcoin::Crypto::Exception::PSBT->raise(
		'field expected but end of stream was reached'
	) unless $pos < length $serialized;

	my $keylen = unpack_compactsize $serialized, \$pos;
	my $keydata = substr $serialized, $pos, $keylen;
	my $keytype = unpack_compactsize $keydata, \(my $keytype_pos = 0);
	$keydata = substr $keydata, $keytype_pos;
	$pos += $keylen;

	my $valuelen = unpack_compactsize $serialized, \$pos;
	my $valuedata = substr $serialized, $pos, $valuelen;
	$pos += $valuelen;

	my $self = $class->new(
		type => [$args->{map_type}, $keytype],
		raw_key => $keydata,
		raw_value => $valuedata,
	);

	Bitcoin::Crypto::Exception::PSBT->raise(
		'serialized field data is corrupted'
	) if !$partial && $pos != length $serialized;

	${$args->{pos}} = $pos
		if $partial;

	return $self;
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	my $enckey = $self->serialized_key;
	my $value = $self->raw_value;

	return join '',
		pack_compactsize(length $enckey),
		$enckey,
		pack_compactsize(length $value),
		$value
		;
}

signature_for dump => (
	method => Object,
	positional => [],
);

sub dump
{
	my ($self) = @_;

	my @result;

	if (defined $self->raw_key) {
		push @result, 'key ' . (to_format [hex => $self->raw_key]) . ':';
		push @result, '> ' . to_format [hex => $self->raw_value];
	}
	else {
		push @result, to_format [hex => $self->raw_value];
	}

	return join "\n", @result;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::PSBT::Field - Single field of a PSBT

=head1 SYNOPSIS

	use Bitcoin::Crypto::PSBT::Field;

	my $field = Bitcoin::Crypto::PSBT::Field->new(
		type => 'PSBT_IN_OUTPUT_INDEX',
		value => 1,
	);

	$psbt->add_field($field, 1);

=head1 DESCRIPTION

This is a helper class which represents a single PSBT field.

While fields hold bytestring data, Bitcoin::Crypto defines some serializers and
deserializers to make it easier to handle the keys and values. These try to
DWIM and should be pretty straightforward, for example
C<PSBT_GLOBAL_UNSIGNED_TX> deserializes into an object of
L<Bitcoin::Crypto::Transaction>. Serializers are not currently documented, so
reading the source of L<Bitcoin::Crypto::PSBT::FieldType> may be required if it
isn't clear how they are implemented for a specific field.

Reading the value through L</raw_value> will return a bytestring, but reading
thourgh C<value> will use the deserializer. Calling C<set_value> will use the
serializer to update L</raw_value>. The field only holds raw data and uses the
serializers to update it as a convenience.

=head1 INTERFACE

=head2 Attributes

=head3 map

The L<Bitcoin::Crypto::PSBT::Map> object this field belongs to. Field can only
belong to a single map at a time. There is no need to set it manually, it will
be set when adding the field to a map.

I<writer:> C<set_map>

=head3 type

B<Required in the constructor>. The type of the field. Must be an instance of
L<Bitcoin::Crypto::PSBT::FieldType>. Can be coerced from a C<PSBT_*> field name.

=head3 raw_key

B<Available in the constructor>. Raw bytestring keydata for this field. Only
valid for field types which actually define key data.

To use a dedicated serializer for a key, use C<key> (constructor key), C<key>
(reader method) or C<set_key> (writer method).

I<writer:> C<set_raw_key>

=head3 raw_value

B<Available in the constructor>. Raw bytestring valuedata for this field.

To use a dedicated serializer for a value, use C<value> (constructor key), C<value>
(reader method) or C<set_value> (writer method).

I<writer:> C<set_raw_value>

=head2 Methods

=head3 new

	$field = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 validate

	$object = $object->validate()

Performs a validation of this field. Will throw an exception if the validation
fails. This method is called automatically when a field is added to a map.

=head3 serialized_key

	$bytestring = $object->serialized_key()

Returns a key in the serialized form (compactsize type + key). Used to sort the
keys for the serialized PSBT map.

=head3 to_serialized

	$serialized = $object->to_serialized()

Serializes a field into a bytestring.

=head3 from_serialized

	$object = $class->from_serialized($data, %params)

Deserializes the bytestring C<$data> into a field.

C<%params> can be any of:

=over

=item * C<map_type>

A constant for map type - required.

=item * C<pos>

Position for partial string decoding. Optional. If passed, must be a scalar
reference to an integer value.

This integer will mark the starting position of C<$bytestring> from which to
start decoding. It will be set to the next byte after end of input stream.

=back

=head3 dump

	$text = $object->dump()

Returns a readable description of this field.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * PSBT - general error with the PSBT

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::PSBT>

=back

=cut

