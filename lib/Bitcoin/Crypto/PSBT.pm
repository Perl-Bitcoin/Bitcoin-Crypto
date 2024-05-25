package Bitcoin::Crypto::PSBT;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto qw(btc_transaction);
use Bitcoin::Crypto::PSBT::FieldType;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Util qw(to_format pack_varint unpack_varint);
use Bitcoin::Crypto::Types qw(Defined Object Str ByteStr ArrayRef HashRef PositiveOrZeroInt);

use namespace::clean;

has field 'global_map' => (
	isa => HashRef,
	default => sub { {} },
);

has field 'input_maps' => (
	isa => ArrayRef [HashRef],
	default => sub { [] },
);

has field 'output_maps' => (
	isa => ArrayRef [HashRef],
	default => sub { [] },
);

sub _get_map
{
	my ($self, $maptype, %args) = @_;

	my %map_dispatch = (
		Bitcoin::Crypto::PSBT::FieldType->GLOBAL => {
			method => 'global_map',
			need_index => !!0,
		},
		Bitcoin::Crypto::PSBT::FieldType->INPUT => {
			method => 'input_maps',
			need_index => !!1,
		},
		Bitcoin::Crypto::PSBT::FieldType->OUTPUT => {
			method => 'output_maps',
			need_index => !!1,
		},
	);

	my $dispatch = $map_dispatch{$maptype};
	my $result = $self->can($dispatch->{method})->($self);

	if ($dispatch->{need_index}) {
		Bitcoin::Crypto::Exception::PSBT->raise(
			"map type '$maptype' requires an index"
		) if !defined $args{index};

		$result->[$args{index}] //= {}
			if $args{set};

		$result = $result->[$args{index}];
	}

	return $result;
}

sub _get_map_value_ref
{
	my ($self, $type, %args) = @_;

	my $map = $self->_get_map($type->get_map_type, %args);
	if ($type->has_key_data) {
		Bitcoin::Crypto::Exception::PSBT->raise(
			'get/set of ' . $type->name . ' requires key_data argument'
		) unless length $args{key_data};

		$map = $map->{$type->code};

		return \($map->{$args{key_data}})
			if $args{set} || ($map && exists $map->{$args{key_data}});
	}
	else {
		Bitcoin::Crypto::Exception::PSBT->raise(
			'get/set of ' . $type->name . ' cannot handle key_data argument'
		) if length $args{key_data};

		return \($map->{$type->code})
			if $args{set} || exists $map->{$type->code};
	}

	# not found (when getting)
	return undef;
}

sub _deserialize_map
{
	my ($self, $serialized, %args) = @_;
	my $pos = ${$args{pos}};

	Bitcoin::Crypto::Exception::PSBT->raise(
		'map expected but end of stream was reached'
	) unless $pos < length $serialized;

	# make sure to create map if there isn't one
	$self->_get_map($args{map_type}, %args, set => !!1);

	while ($pos < length $serialized) {
		my $keylen = unpack_varint $serialized, \$pos;
		last if $keylen == 0;

		my $keydata = substr $serialized, $pos, $keylen;
		my $keytype = unpack_varint $keydata, \(my $keytype_pos = 0);
		$keydata = substr $keydata, $keytype_pos;
		$pos += $keylen;

		my $valuelen = unpack_varint $serialized, \$pos;
		my $valuedata = substr $serialized, $pos, $valuelen;
		$pos += $valuelen;

		my $field_type = Bitcoin::Crypto::PSBT::FieldType->get_field_by_code($args{map_type}, $keytype);
		my $value_ref = $self->_get_map_value_ref($field_type, key_data => $keydata, index => $args{index}, set => !!1);

		Bitcoin::Crypto::Exception::PSBT->raise(
			'duplicate field ' . $field_type->name
		) if defined $$value_ref;
		$$value_ref = $valuedata;
	}

	${$args{pos}} = $pos;
}

sub _deserialize_version0
{
	my ($self, $serialized, $pos) = @_;
	my $tx = btc_transaction->from_serialized($self->get_field('PSBT_GLOBAL_UNSIGNED_TX'));
	my $input_count = @{$tx->inputs};
	my $output_count = @{$tx->outputs};

	foreach my $index (0 .. $input_count - 1) {
		$self->_deserialize_map(
			$serialized,
			map_type => Bitcoin::Crypto::PSBT::FieldType->INPUT,
			pos => \$pos,
			index => $index,
		);
	}

	foreach my $index (0 .. $output_count - 1) {
		$self->_deserialize_map(
			$serialized,
			map_type => Bitcoin::Crypto::PSBT::FieldType->OUTPUT,
			pos => \$pos,
			index => $index,
		);
	}

	Bitcoin::Crypto::Exception::PSBT->raise(
		'serialized PSBT data is corrupted'
	) if $pos != length $serialized;
}

sub _deserialize_version2
{
	...;
}

sub _check_integrity
{
	my ($self) = @_;
	my $version = $self->version;

	my $check_field = sub {
		my ($name, $index) = @_;

		Bitcoin::Crypto::Exception::PSBT->raise(
			"PSBT field $name is required in version $version"
		) unless defined $self->get_field($name, (defined $index ? (index => $index) : ()));
	};

	my $required_fields = Bitcoin::Crypto::PSBT::FieldType->get_fields_required_in_version($version);
	foreach my $field (@{$required_fields}) {

		# NOTE: no required fields need keydata

		my $field_type = $field->get_map_type;
		if ($field_type eq Bitcoin::Crypto::PSBT::FieldType->GLOBAL) {
			$check_field->($field->name);
		}
		elsif ($field_type eq Bitcoin::Crypto::PSBT::FieldType->INPUT) {
			for my $input_index (0 .. $self->input_count) {
				$check_field->($field->name, index => $input_index);
			}
		}
		elsif ($field_type eq Bitcoin::Crypto::PSBT::FieldType->OUTPUT) {
			for my $output_index (0 .. $self->output_count) {
				$check_field->($field->name, index => $output_index);
			}
		}
	}
}

signature_for input_count => (
	method => Object,
	positional => []
);

sub input_count
{
	my ($self) = @_;

	return scalar @{$self->input_maps};
}

signature_for output_count => (
	method => Object,
	positional => []
);

sub output_count
{
	my ($self) = @_;

	return scalar @{$self->output_maps};
}

signature_for set_field => (
	method => Object,
	head => [Str, ByteStr],
	named => [
		key_data => ByteStr,
		{optional => !!1},
		index => PositiveOrZeroInt,
		{optional => !!1},
	],
	bless => !!0,
);

sub set_field
{
	my ($self, $name, $value, $args) = @_;

	my $type = Bitcoin::Crypto::PSBT::FieldType->get_field_by_name($name);
	${$self->_get_map_value_ref($type, %$args, set => !!1)} = $value;

	return $self;
}

signature_for get_field => (
	method => Object,
	head => [Str],
	named => [
		key_data => ByteStr,
		{optional => !!1},
		index => PositiveOrZeroInt,
		{optional => !!1},
	],
	bless => !!0,
);

sub get_field
{
	my ($self, $name, $args) = @_;

	my $type = Bitcoin::Crypto::PSBT::FieldType->get_field_by_name($name);
	my $ref = $self->_get_map_value_ref($type, %$args);

	return $$ref if defined $ref;
	return undef;
}

signature_for version => (
	method => Object,
	positional => [],
);

sub version
{
	my ($self) = @_;

	return $self->get_field('PSBT_GLOBAL_VERSION') // 0;
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

	$self->_deserialize_map(
		$serialized,
		map_type => Bitcoin::Crypto::PSBT::FieldType->GLOBAL,
		pos => \$pos,
	);

	my $version = $self->version;
	my $method = "_deserialize_version" . $version;

	Bitcoin::Crypto::Exception::PSBT->raise(
		"PSBT version $version is not supported"
	) unless $self->can($method);
	$self->$method($serialized, $pos);

	$self->_check_integrity;

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

	my $add_line = sub {
		my ($line, $level) = @_;
		$level //= 0;

		push @result, ('> ' x $level) . $line;
	};

	my $dump_map = sub {
		my ($name, $maptype, $map) = @_;

		$add_line->($name . ' map:');
		foreach my $key (keys %{$map}) {
			my $type = Bitcoin::Crypto::PSBT::FieldType->get_field_by_code($maptype, $key);
			my $value = $map->{$key};

			$add_line->($type->name . ':', 1);
			if (ref $value eq 'HASH') {
				foreach my $keydata (keys %{$value}) {
					$add_line->('key ' . (to_format [hex => $keydata]) . ':', 2);
					$add_line->(to_format [hex => $value->{$keydata}], 3);
				}
			}
			else {
				$add_line->(to_format [hex => $value], 2);
			}
		}
	};

	$dump_map->('Global', Bitcoin::Crypto::PSBT::FieldType->GLOBAL, $self->global_map);

	foreach my $input_number (0 .. $#{$self->input_maps}) {
		$dump_map->(
			"Input[$input_number]", Bitcoin::Crypto::PSBT::FieldType->INPUT,
			$self->input_maps->[$input_number]
		);
	}

	foreach my $output_number (0 .. $#{$self->output_maps}) {
		$dump_map->(
			"Output[$output_number]",
			Bitcoin::Crypto::PSBT::FieldType->OUTPUT,
			$self->output_maps->[$output_number]
		);
	}

	return join "\n", @result;
}

1;

