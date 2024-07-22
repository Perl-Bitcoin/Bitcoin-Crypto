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

	push @{$self->maps}, Bitcoin::Crypto::PSBT::Map->from_serialized(
		$serialized,
		map_type => Bitcoin::Crypto::Constants::psbt_global_map,
		pos => \$pos,
	);

	foreach my $index (0 .. $self->input_count - 1) {
		push @{$self->maps}, Bitcoin::Crypto::PSBT::Map->from_serialized(
			$serialized,
			map_type => Bitcoin::Crypto::Constants::psbt_input_map,
			pos => \$pos,
			index => $index,
		);
	}

	foreach my $index (0 .. $self->output_count - 1) {
		push @{$self->maps}, Bitcoin::Crypto::PSBT::Map->from_serialized(
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

