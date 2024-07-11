package Bitcoin::Crypto::PSBT::Map;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Maybe Enum ByteStr PositiveOrZeroInt Object InstanceOf PSBTMapType);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;

has param 'type' => (
	isa => PSBTMapType,
);

has param 'index' => (
	isa => Maybe [PositiveOrZeroInt],
	default => undef,
);

has field 'fields' => (
	default => sub { [] },
);

sub BUILD
{
	my ($self) = @_;

	Bitcoin::Crypto::Exception::PSBT->raise(
		'Map of type ' . $self->type . ' requires an index'
	) if $self->need_index && !defined $self->index;
}

signature_for name => (
	method => Object,
	positional => [],
);

sub name
{
	my ($self) = @_;
	my %dispatch = (
		Bitcoin::Crypto::Constants::psbt_global_map => 'Global',
		Bitcoin::Crypto::Constants::psbt_input_map => 'Input',
		Bitcoin::Crypto::Constants::psbt_output_map => 'Output',
	);

	my $name = $dispatch{$self->type};
	if ($self->need_index) {
		$name .= '[' . $self->index . ']';
	}

	return $name;
}

signature_for need_index => (
	method => Object,
	positional => [],
);

sub need_index
{
	my ($self) = @_;
	my $type = $self->type;

	return 1 == grep { $type eq $_ }
		Bitcoin::Crypto::Constants::psbt_input_map,
		Bitcoin::Crypto::Constants::psbt_output_map,
		;
}

signature_for add => (
	method => Object,
	positional => [InstanceOf ['Bitcoin::Crypto::PSBT::Field']],
);

sub add
{
	my ($self, $field) = @_;

	Bitcoin::Crypto::Exception::PSBT->raise(
		'This field is already used in another map'
	) if $field->map;

	$field->set_map($self);
	push @{$self->fields}, $field;

	return;
}

sub _integrity_violation
{
	my ($self, $type, $desc) = @_;
	my $map_name = $self->name;
	my $type_name = $type->name;

	Bitcoin::Crypto::Exception::PSBT->raise(
		"Map $map_name, type $type_name: $desc"
	);
}

sub _check_integrity
{
	my ($self, $field) = @_;
	my @results = grep { $_ != $field } $self->_find($field->type, $field->raw_key);

	$self->_integrity_violation($field->type, 'duplicate field')
		if @results > 0;

	return;
}

sub _find
{
	my ($self, $type, $key) = @_;
	my $code = $type->code;
	my $has_key = defined $type->key_data && defined $key;

	my @found;
	foreach my $field (@{$self->fields}) {
		next unless $field->type->code == $code;
		push @found, $field
			if !$has_key || $key eq $field->raw_key;
	}

	# force list to have it return the last item in the scalar context instead
	# of number of items
	return @found[0 .. $#found];
}

signature_for find => (
	method => Object,
	positional => [
		InstanceOf ['Bitcoin::Crypto::PSBT::FieldType'],
		Maybe [ByteStr], {default => undef}
	],
);

sub find
{
	my ($self, $type, $key) = @_;

	return $self->_find($type, $key);
}

1;

