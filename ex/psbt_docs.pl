use v5.14;
use warnings;

use Bitcoin::Crypto::PSBT::FieldType;

my %maps = (
	global => 'Global map',
	in => 'Input map',
	out => 'Output map',
);

my @all_fields = (
	@{Bitcoin::Crypto::PSBT::FieldType->get_fields_available_in_version(0)},
	@{Bitcoin::Crypto::PSBT::FieldType->get_fields_available_in_version(2)},
);

my %mapped_fields;
foreach my $field (@all_fields) {
	$mapped_fields{$field->map_type}{$field->code} = $field;
}

foreach my $map (sort keys %maps) {
	say '=head2 ' . $maps{$map};
	say '';
	say '=over';
	say '';

	foreach my $field_code (sort { $a <=> $b } keys %{$mapped_fields{$map}}) {
		my $field = $mapped_fields{$map}{$field_code};

		say '=item * ' . $field->name;
		say '';
		say 'B<Key data:> ' . ($field->key_data // '<none>');
		say '';
		say 'B<Value data:> ' . $field->value_data;
		say '';
	}

	say '=back';
	say '';
}

__END__

=head1 PSBT docs example

This example shows how to loop through all PSBT fields. It generates a
documentation of all currently supproted PSBT fields.

