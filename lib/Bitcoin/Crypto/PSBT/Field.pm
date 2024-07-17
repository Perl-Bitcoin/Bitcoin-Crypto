package Bitcoin::Crypto::PSBT::Field;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Object Maybe Defined ByteStr InstanceOf PSBTFieldType);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::PSBT::FieldType;

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
	my ($self) = @_;

	if (defined $self->raw_key && !defined $self->type->key_data) {
		Bitcoin::Crypto::Exception::PSBT->raise(
			'Field ' . $self->type->name . ' does not define key data'
		) if length $self->raw_key;

		$self->_set_raw_key(undef);
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
			if (defined $self->type->key_data) {
				unshift @args, $self->key;
			}

			$self->type->validator->(@args)
				if $self->type->has_validator;
		},
		'validation failed for type ' . $self->type->name
	);

	return !!1;
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
	) if !defined $self->type->key_data;

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

	$self->set_raw_key($self->type->key_serializer($key));
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

	$self->set_raw_value($self->type->serializer($value));
	return;
}

signature_for set_map => (
	method => Object,
	positional => [Defined],
);

sub set_map
{
	my ($self, $map) = @_;

	$self->_set_map($map);
	$map->_check_integrity($self);
	return;
}

1;

