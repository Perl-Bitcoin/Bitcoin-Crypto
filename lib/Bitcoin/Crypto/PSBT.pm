package Bitcoin::Crypto::PSBT;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use List::Util qw(any);

use Bitcoin::Crypto::PSBT::Map;
use Bitcoin::Crypto::PSBT::Field;
use Bitcoin::Crypto::PSBT::FieldType;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;

use namespace::clean;

has field 'maps' => (
	isa => ArrayRef [InstanceOf ['Bitcoin::Crypto::PSBT::Map']],
	default => sub { [] },
);

sub _get_map
{
	my ($self, $maptype, %args) = @_;

	my $found_map;
	foreach my $map (@{$self->maps}) {
		next unless $map->type eq $maptype;
		next if $map->need_index && (!defined $args{index} || $map->index ne $args{index});

		$found_map = $map;
		last;
	}

	if (!$found_map && $args{set}) {
		$found_map = Bitcoin::Crypto::PSBT::Map::->new(
			type => $maptype,
			index => $args{index},
		);

		push @{$self->maps}, $found_map;
	}

	return $found_map;
}

signature_for input_count => (
	method => Object,
	positional => []
);

sub input_count
{
	my ($self) = @_;
	my $version = $self->version;

	if ($version == 0) {
		my $tx = $self->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value;
		return scalar @{$tx->inputs};
	}
	elsif ($version == 2) {
		return $self->get_field('PSBT_GLOBAL_INPUT_COUNT')->value;
	}
}

signature_for output_count => (
	method => Object,
	positional => []
);

sub output_count
{
	my ($self) = @_;
	my $version = $self->version;

	if ($version == 0) {
		my $tx = $self->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value;
		return scalar @{$tx->outputs};
	}
	elsif ($version == 2) {
		return $self->get_field('PSBT_GLOBAL_OUTPUT_COUNT')->value;
	}
}

signature_for get_field => (
	method => Object,
	positional => [PSBTFieldType, Maybe [PositiveOrZeroInt], {default => undef}],
);

sub get_field
{
	my ($self, $type, $index) = @_;

	my @values = $self->get_all_fields($type, $index);
	Bitcoin::Crypto::Exception::PSBT->raise(
		'Could not get value for field ' . $type->name . ': found ' . @values . ' values in PSBT'
	) unless @values == 1;

	return $values[0];
}

signature_for get_all_fields => (
	method => Object,
	positional => [PSBTFieldType, Maybe [PositiveOrZeroInt], {default => undef}],
);

sub get_all_fields
{
	my ($self, $type, $index) = @_;

	my $map = $self->_get_map($type->map_type, index => $index);
	return () unless $map;
	return $map->find($type);
}

signature_for add_field => (
	method => Object,
	positional => [ArrayRef, {slurpy => !!1}],
);

sub add_field
{
	my ($self, $data) = @_;
	my $field;
	my $index;

	if ((@$data == 1 || @$data == 2) && blessed $data->[0] && $data->[0]->isa('Bitcoin::Crypto::PSBT::Field')) {
		($field, $index) = @$data;
	}
	else {
		my %data = @$data;
		$index = delete $data{index};
		$field = Bitcoin::Crypto::PSBT::Field->new(%data);
	}

	my $map = $self->_get_map($field->type->map_type, index => $index, set => !!1);
	$map->add($field);

	return $self;
}

signature_for version => (
	method => Object,
	positional => [],
);

sub version
{
	my ($self) = @_;

	my $version = $self->get_all_fields('PSBT_GLOBAL_VERSION');
	$version = $version ? $version->value : 0;

	Bitcoin::Crypto::Exception::PSBT->raise(
		"PSBT version $version is not supported"
	) unless any { $_ == $version } 0, 2;

	return $version;
}

signature_for from_serialized => (
	method => Str,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $serialized) = @_;
	my $self = $class->new;

	my $pos = length Bitcoin::Crypto::Constants::psbt_magic;
	my $magic = substr $serialized, 0, $pos;

	Bitcoin::Crypto::Exception::PSBT->raise(
		'serialized string does not contain the PSBT header'
	) unless $magic eq Bitcoin::Crypto::Constants::psbt_magic;

	push @{$self->maps}, Bitcoin::Crypto::PSBT::Map::->from_serialized(
		$serialized,
		map_type => Bitcoin::Crypto::Constants::psbt_global_map,
		pos => \$pos,
	);

	foreach my $index (0 .. $self->input_count - 1) {
		push @{$self->maps}, Bitcoin::Crypto::PSBT::Map::->from_serialized(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_input_map,
			pos => \$pos,
			index => $index,
		);
	}

	foreach my $index (0 .. $self->output_count - 1) {
		push @{$self->maps}, Bitcoin::Crypto::PSBT::Map::->from_serialized(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_output_map,
			pos => \$pos,
			index => $index,
		);
	}

	Bitcoin::Crypto::Exception::PSBT->raise(
		'serialized PSBT data is corrupted'
	) if $pos != length $serialized;

	$self->check;

	return $self;
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	$self->check;

	my $serialized = Bitcoin::Crypto::Constants::psbt_magic;
	$serialized .= $self->_get_map(Bitcoin::Crypto::Constants::psbt_global_map)->to_serialized;

	for my $input_index (0 .. $self->input_count - 1) {
		$serialized .= $self->_get_map(Bitcoin::Crypto::Constants::psbt_input_map, index => $input_index)
			->to_serialized;
	}

	for my $output_index (0 .. $self->output_count - 1) {
		$serialized .= $self->_get_map(Bitcoin::Crypto::Constants::psbt_output_map, index => $output_index)
			->to_serialized;
	}

	return $serialized;
}

signature_for check => (
	method => Object,
	positional => [],
);

sub check
{
	my ($self) = @_;
	my $version = $self->version;

	my $required_fields = Bitcoin::Crypto::PSBT::FieldType->get_fields_required_in_version($version);
	foreach my $field_type (@{$required_fields}) {
		my @maps;

		if ($field_type->map_type eq Bitcoin::Crypto::Constants::psbt_global_map) {
			@maps = ($self->_get_map($field_type->map_type));
		}
		elsif ($field_type->map_type eq Bitcoin::Crypto::Constants::psbt_input_map) {
			@maps = map { $self->_get_map($field_type->map_type, index => $_) } 0 .. $self->input_count - 1;
		}
		elsif ($field_type->map_type eq Bitcoin::Crypto::Constants::psbt_output_map) {
			@maps = map { $self->_get_map($field_type->map_type, index => $_) } 0 .. $self->output_count - 1;
		}

		foreach my $map (@maps) {
			my @values = defined $map ? $map->find($field_type) : ();
			Bitcoin::Crypto::Exception::PSBT->raise(
				"PSBT field " . $field_type->name . " is required in version $version"
			) unless @values == 1;
		}
	}

	foreach my $map (@{$self->maps}) {
		foreach my $field (@{$map->fields}) {
			Bitcoin::Crypto::Exception::PSBT->raise(
				"PSBT field " . $field->type->name . " is not available in version $version"
			) unless $field->type->available_in_version($version);
		}
	}

	return $self;
}

signature_for dump => (
	method => Object,
	positional => [],
);

sub dump
{
	my ($self) = @_;
	my @result;

	my @maps = sort {
		my $ret = $a->type cmp $b->type;
		if ($ret == 0 && $a->need_index) {
			$ret = $a->index <=> $b->index;
		}

		$ret;
	} @{$self->maps};

	foreach my $map (@maps) {
		push @result, $map->name . ' map:';

		my $dumped = $map->dump;
		push @result, $dumped
			if length $dumped;
	}

	return join "\n", @result;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::PSBT - Partially Signed Bitcoin Transactions

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_psbt);

	# import PSBT from a serialized form
	my $psbt = btc_psbt->from_serialized([base64 => $psbt_string]);

	# dump in readable format
	print $psbt->dump;

	# get a single PSBT field
	my $field = $psbt->get_field('PSBT_GLOBAL_TX_VERSION');

	# get decoded field key and value
	my $key = $field->key;
	my $value = $field->value;

	# get all PSBT fields of a given type
	my @fields = $psbt->get_all_fields('PSBT_GLOBAL_PROPRIETARY');

=head1 DESCRIPTION

This is a class implementing the PSBT format as described in BIP174 and
BIP370. It currently supports versions 0 and 2 of the spec. It allows
serialization, deserialization, validation and access to PSBT fields. It
currently does not support the roles defined by the PSBT documents, so all the
operations on PSBTs (like adding inputs or creating a final transaction out of
it) must be done manually.

PSBT consists of a number of maps: one global, one for each transaction input
and one for each transaction output. Each map holds a number of fields. Each
field has a value and can optionally have extra key data.

=head1 INTERFACE

=head2 Attributes

=head3 maps

An array reference of PSBT internal maps - objects of class
L<Bitcoin::Crypto::PSBT::Map>. It should seldom be handled manually - use
L</get_field>, L</get_all_fields> and L</add_field> to access fields of
specific map.

=head2 Methods

=head3 new

	$psbt = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 version

	$version = $object->version()

Returns the version of the PSBT (C<0> or C<2>).

=head3 input_count

	$int = $object->input_count()

Returns the number of inputs the PSBT defines.

=head3 output_count

	$int = $object->output_count()

Returns the number of outputs the PSBT defines.

=head3 get_field

	$field = $object->get_field($field_type_name, $map_index = undef)

Tries to get a field of C<$field_type_name> as defined in BIP174, for example
C<PSBT_GLOBAL_UNSIGNED_TX>. If the field is from input or output maps, it also
requires C<$map_index> to be passed (0-based index of the input or output).

Returns an instance of L<Bitcoin::Crypto::PSBT::Field>, which you can use to
access key and value data.

If there isn't exactly one field with this type in the map, it will throw an
exception. This allows you to write the following without checking the return
value of the function:

	my $output_index_0 = $object->get_field('PSBT_IN_OUTPUT_INDEX', 0)->value;

See L</get_all_fields> for a variant which does not check the field count.

=head3 get_all_fields

	@fields = $object->get_all_fields($field_type_name, $map_index = undef)

Same as L</get_field>, but will return all the fields of given type from a
given map. It may be used if the field exists, or to get multiple fields with
different key data.

The return value is a list (not an array), so using it in scalar context will
get the last found field (as opposed to a field count).

=head3 add_field

	$object = $object->add_field(%field_data)
	$object = $object->add_field($field_object, $map_index = undef)

Adds a new field to the PSBT. It can be run either with C<%field_data> (a hash
arguments for the L<Bitcoin::Crypto::PSBT::Field/new>) or with C<$field_object>
(constructed L<Bitcoin::Crypto::PSBT::Field>) and C<$map_index>.

If passing C<%field_data> hash, it can contain an additional C<index> key to
represent C<$map_index>. The field will be constructed and added to the map.
Adding the index to a map triggers its validations, so it must be complete
enough to pass them. For this reason, sometimes it could be more preferable to
construct and fill the field by hand before adding it to the PSBT.

Note that a field cannot be used in more than one map at a time.

=head3 check

	$object = $object->check()

Checks the internal state of PSBT fields and throws an exception if it is
invalid. Returns the object itself.

=head3 to_serialized

	$serialized = $object->to_serialized()

Serializes a PSBT into a bytestring. L</check> is called automatically before
serializing.

=head3 from_serialized

	$object = $class->from_serialized($data)

Deserializes the bytestring C<$data> into a PSBT object. L</check> is called
automatically after deserializing.

=head3 dump

	$text = $object->dump()

Returns a readable description of all the maps in the PSBT.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * PSBT - general error with the PSBT

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::PSBT::Field>

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

