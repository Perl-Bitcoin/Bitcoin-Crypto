package Bitcoin::Crypto::Role::PSBT::Combiner;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;
use Types::Common -sigs;

use Bitcoin::Crypto::Util qw(to_format);

sub _resolve_conflict_PSBT_GLOBAL_TX_MODIFIABLE
{
	my ($self, $field, $other_field) = @_;

	my $v1 = $field->value;
	my $v2 = $other_field->value;

	$v1->{inputs_modifiable} &&= $v2->{inputs_modifiable};
	$v1->{outputs_modifiable} &&= $v2->{outputs_modifiable};
	$v1->{has_sighash_single} ||= $v2->{has_sighash_single};

	$field->set_value($v1);
}

sub _resolve_conflict
{
	my ($self, $field, $other_field) = @_;

	my $type = $field->type->name;
	my $method = $self->can("_resolve_conflict_$type");

	# only resolve conflicts of certain fields, reject other conflicts with an exception
	Bitcoin::Crypto::Exception::PSBT->raise(
		'combining PSBTs failed - conflicting values for field ' . $field->type->name
			. ($field->type->has_key_data ? ' and key ' . to_format [hex => $field->raw_key] : '')
	) unless $method;

	$self->$method($field, $other_field);
}

# compares field lists for one field type and possibly one index
sub _compare_field_lists
{
	my ($self, $list_new, $list_old) = @_;
	my @missing_fields;

	foreach my $field (@{$list_new}) {
		my $uses_key = $field->type->has_key_data;
		my $found = !!0;
		foreach my $other_field (@{$list_old}) {
			next if $uses_key && $field->raw_key ne $other_field->raw_key;

			# NOTE: resolve conflict on $other_field as first argument - it
			# must've already be cloned and belong to new psbt, so it must be
			# changed directly instead of cloning
			$self->_resolve_conflict($other_field, $field)
				if $field->raw_value ne $other_field->raw_value;

			$found = !!1;
			last;
		}

		push @missing_fields, $field
			unless $found;
	}

	return @missing_fields;
}

signature_for combine => (
	method => !!1,
	positional => [
		ArrayRef [InstanceOf ['Bitcoin::Crypto::PSBT']],
		{slurpy => !!1},
	],
);

sub combine
{
	my ($self, $others) = @_;

	my @list = @{$others};
	unshift @list, $self if ref $self;
	Bitcoin::Crypto::Exception::PSBT->raise(
		'combining PSBTs failed - need at least two PSBTs'
	) unless @list > 1;

	my $id = $list[0]->get_id;
	my $new_psbt = $self->new(strict => $list[0]->strict);
	foreach my $psbt (@list) {
		Bitcoin::Crypto::Exception::PSBT->raise(
			'combining PSBTs failed - not the same PSBT'
		) unless $psbt->get_id eq $id;

		foreach my $field_info ($psbt->list_fields) {
			my ($type, $index) = @{$field_info};
			my @fields = $psbt->get_all_fields($type, $index);
			my @existing_fields = $new_psbt->get_all_fields($type, $index);

			my @to_add = $self->_compare_field_lists(\@fields, \@existing_fields);
			foreach my $field (@to_add) {
				$new_psbt->add_field($field->clone, $index);
			}
		}
	}

	return $new_psbt->check;
}

1;

