package Bitcoin::Crypto::PSBT;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use List::Util qw(any);

use Bitcoin::Crypto::PSBT::Map;
use Bitcoin::Crypto::PSBT::Field;
use Bitcoin::Crypto::PSBT::FieldType;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Util qw(to_format pack_compactsize unpack_compactsize);
use Bitcoin::Crypto::Types qw(Object Str InstanceOf ByteStr ArrayRef PositiveOrZeroInt Maybe PSBTFieldType);

use namespace::clean;

has field 'maps' => (
	isa => ArrayRef [InstanceOf ['Bitcoin::Crypto::PSBT::Map']],
	default => sub { [] },
);

sub BUILD
{
	my ($self) = @_;

	# create a global map
	$self->_get_map(Bitcoin::Crypto::Constants::psbt_global_map, set => !!1);
}

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
		$found_map = Bitcoin::Crypto::PSBT::Map->new(
			type => $maptype,
			index => $args{index},
		);

		push @{$self->maps}, $found_map;
	}

	return $found_map;
}

sub _deserialize_map
{
	my ($self, $serialized, %args) = @_;
	my $pos = ${$args{pos}};

	Bitcoin::Crypto::Exception::PSBT->raise(
		'map expected but end of stream was reached'
	) unless $pos < length $serialized;

	# make sure to create a map if there isn't one
	my $map = $self->_get_map($args{map_type}, index => $args{index}, set => !!1);

	while ($pos < length $serialized) {
		my $keylen = unpack_compactsize $serialized, \$pos;
		last if $keylen == 0;

		my $keydata = substr $serialized, $pos, $keylen;
		my $keytype = unpack_compactsize $keydata, \(my $keytype_pos = 0);
		$keydata = substr $keydata, $keytype_pos;
		$pos += $keylen;

		my $valuelen = unpack_compactsize $serialized, \$pos;
		my $valuedata = substr $serialized, $pos, $valuelen;
		$pos += $valuelen;

		my $item = Bitcoin::Crypto::PSBT::Field->new(
			type => [$args{map_type}, $keytype],
			raw_key => $keydata,
			raw_value => $valuedata,
		);

		$map->add($item);
	}

	${$args{pos}} = $pos;
}

sub _serialize_map
{
	my ($self, %args) = @_;

	my $map = $self->_get_map($args{map_type}, index => $args{index});
	my %to_encode;

	foreach my $item (@{$map->fields}) {
		my $key = $item->raw_key;
		my $value = $item->raw_value;
		my $enckey = pack_compactsize($item->type->code) . ($key // '');

		$to_encode{$enckey} = $value;
	}

	my @keypairs;
	foreach my $key (sort keys %to_encode) {
		push @keypairs, join '',
			pack_compactsize(length $key),
			$key,
			pack_compactsize(length $to_encode{$key}),
			$to_encode{$key}
			;
	}

	return join('', @keypairs) . pack_compactsize(0);
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

	$self->_deserialize_map(
		$serialized,
		map_type => Bitcoin::Crypto::Constants::psbt_global_map,
		pos => \$pos,
	);

	foreach my $index (0 .. $self->input_count - 1) {
		$self->_deserialize_map(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_input_map,
			pos => \$pos,
			index => $index,
		);
	}

	foreach my $index (0 .. $self->output_count - 1) {
		$self->_deserialize_map(
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
	$serialized .= $self->_serialize_map(map_type => Bitcoin::Crypto::Constants::psbt_global_map);

	for my $input_index (0 .. $self->input_count - 1) {
		$serialized .= $self->_serialize_map(
			map_type => Bitcoin::Crypto::Constants::psbt_input_map,
			index => $input_index,
		);
	}

	for my $output_index (0 .. $self->output_count - 1) {
		$serialized .= $self->_serialize_map(
			map_type => Bitcoin::Crypto::Constants::psbt_output_map,
			index => $output_index,
		);
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

	my $add_line = sub {
		my ($line, $level) = @_;
		$level //= 0;

		push @result, ('> ' x $level) . $line;
	};

	my @maps = sort {
		my $ret = $a->type cmp $b->type;
		if ($ret == 0 && $a->need_index) {
			$ret = $a->index <=> $b->index;
		}

		$ret;
	} @{$self->maps};

	foreach my $map (@maps) {
		$add_line->($map->name . ' map:');

		my %fields;
		foreach my $item (@{$map->fields}) {
			push @{$fields{$item->type->name}}, $item;
		}

		foreach my $key (sort keys %fields) {
			$add_line->("${key}:", 1);
			foreach my $item (@{$fields{$key}}) {
				my $line = 2;
				if (defined $item->raw_key) {
					$add_line->('key ' . (to_format [hex => $item->raw_key]) . ':', $line++);
				}
				$add_line->(to_format [hex => $item->raw_value], $line);
			}
		}
	}

	return join "\n", @result;
}

1;

