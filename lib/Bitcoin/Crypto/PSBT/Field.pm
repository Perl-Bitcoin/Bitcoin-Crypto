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

	if (defined $self->raw_key && !defined $self->type->key_data) {
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
			if (defined $self->type->key_data) {
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

