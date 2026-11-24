package Bitcoin::Crypto::Role::PSBT::Combiner;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;
use Types::Common -sigs;

use Bitcoin::Crypto::Util qw(to_format);

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
			$found = !!1;

			Bitcoin::Crypto::Exception::PSBT->raise(
				'combining PSBTs failed - conflicting values for field ' . $field->type->name
					. ($uses_key ? ' and key ' . to_format [hex => $field->raw_key] : '')
			) unless $field->raw_value eq $other_field->raw_value;
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

	my $id = $self->get_id;
	my $new_psbt = $self->new(strict => $self->strict);
	foreach my $psbt ($self, @{$others}) {
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

