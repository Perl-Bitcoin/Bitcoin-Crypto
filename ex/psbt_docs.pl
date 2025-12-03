use v5.14;
use warnings;

use Bitcoin::Crypto::PSBT::FieldType;

my %maps = (
	global => 'Global map',
	in => 'Input map',
	out => 'Output map',
);

foreach my $map (sort keys %maps) {
	say '=head2 ' . $maps{$map};
	say '';
	say '=over';
	say '';

	for (my $code = 0 ; ; ++$code) {
		my $field = Bitcoin::Crypto::PSBT::FieldType->get_field_by_code($map, $code);
		last if $field->name eq 'UNKNOWN';

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

