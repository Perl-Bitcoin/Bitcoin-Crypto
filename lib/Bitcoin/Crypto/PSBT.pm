package Bitcoin::Crypto::PSBT;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

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
		my $enckey = pack_compactsize($item->type->code) . $key // '';

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

sub _deserialize_version0
{
	my ($self, $serialized, $pos_ref) = @_;
	my $tx = $self->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value;
	my $input_count = @{$tx->inputs};
	my $output_count = @{$tx->outputs};

	foreach my $index (0 .. $input_count - 1) {
		$self->_deserialize_map(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_input_map,
			pos => $pos_ref,
			index => $index,
		);
	}

	foreach my $index (0 .. $output_count - 1) {
		$self->_deserialize_map(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_output_map,
			pos => $pos_ref,
			index => $index,
		);
	}
}

sub _deserialize_version2
{
	my ($self, $serialized, $pos_ref) = @_;
	my $input_count = $self->get_field('PSBT_GLOBAL_INPUT_COUNT')->value;
	my $output_count = $self->get_field('PSBT_GLOBAL_OUTPUT_COUNT')->value;

	foreach my $index (0 .. $input_count - 1) {
		$self->_deserialize_map(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_input_map,
			pos => $pos_ref,
			index => $index,
		);
	}

	foreach my $index (0 .. $output_count - 1) {
		$self->_deserialize_map(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_output_map,
			pos => $pos_ref,
			index => $index,
		);
	}
}

sub _check_integrity
{
	my ($self) = @_;
	my $version = $self->version;

	my $check_field = sub {
		my ($name, $index) = @_;

		my @values = $self->get_field($name, $index);
		Bitcoin::Crypto::Exception::PSBT->raise(
			"PSBT field $name is required in version $version"
		) unless @values == 1;
	};

	my $required_fields = Bitcoin::Crypto::PSBT::FieldType->get_fields_required_in_version($version);
	foreach my $field (@{$required_fields}) {

		# NOTE: no required fields need keydata

		my $field_type = $field->get_map_type;
		if ($field_type eq Bitcoin::Crypto::Constants::psbt_global_map) {
			$check_field->($field->name);
		}
		elsif ($field_type eq Bitcoin::Crypto::Constants::psbt_input_map) {
			for my $input_index (0 .. $self->input_count - 1) {
				$check_field->($field->name, $input_index);
			}
		}
		elsif ($field_type eq Bitcoin::Crypto::Constants::psbt_output_map) {
			for my $output_index (0 .. $self->output_count - 1) {
				$check_field->($field->name, $output_index);
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

	return scalar grep { $_->type eq Bitcoin::Crypto::Constants::psbt_input_map } @{$self->maps};
}

signature_for output_count => (
	method => Object,
	positional => []
);

sub output_count
{
	my ($self) = @_;

	return scalar grep { $_->type eq Bitcoin::Crypto::Constants::psbt_output_map } @{$self->maps};
}

signature_for get_field => (
	method => Object,
	positional => [PSBTFieldType, Maybe [PositiveOrZeroInt], {default => undef}],
);

sub get_field
{
	my ($self, $type, $index) = @_;

	my $map = $self->_get_map($type->get_map_type, index => $index);
	return () unless $map;
	return $map->find($type);
}

signature_for version => (
	method => Object,
	positional => [],
);

sub version
{
	my ($self) = @_;

	my $version = $self->get_field('PSBT_GLOBAL_VERSION');
	return $version ? $version->value : 0;
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

	my $version = $self->version;
	my $method = "_deserialize_version" . $version;

	Bitcoin::Crypto::Exception::PSBT->raise(
		"PSBT version $version is not supported"
	) unless $self->can($method);
	$self->$method($serialized, \$pos);

	Bitcoin::Crypto::Exception::PSBT->raise(
		'serialized PSBT data is corrupted'
	) if $pos != length $serialized;

	$self->_check_integrity;

	return $self;
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	$self->_check_integrity;

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
		foreach my $item (@{$map->fields}) {
			$add_line->($item->type->name . ':', 1);
			if (defined $item->raw_key) {
				$add_line->('key ' . (to_format [hex => $item->raw_key]) . ':', 2);
			}
			$add_line->(to_format [hex => $item->raw_value], 3);
		}
	}

	return join "\n", @result;
}

1;

