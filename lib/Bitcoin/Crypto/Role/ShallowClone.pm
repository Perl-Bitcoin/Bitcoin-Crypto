package Bitcoin::Crypto::Role::ShallowClone;

use v5.10;
use strict;
use warnings;

use Type::Params -sigs;
use Bitcoin::Crypto::Types qw(Object);
use Moo::Role;

signature_for clone => (
	method => Object,
	positional => [
	],
);

# Clones up to two levels deep - main reference and any plain hash / array
# references inside it
sub clone
{
	my ($self) = @_;

	my %new_self;
	foreach my $key (keys %{$self}) {
		my $value = $self->{$key};
		my $ref = ref $value;

		if ($ref eq 'ARRAY') {
			$new_self{$key} = [@{$value}];
		}
		elsif ($ref eq 'HASH') {
			$new_self{$key} = {%{$value}};
		}
		else {
			$new_self{$key} = $value;
		}
	}

	# Don't use the constructor because not all state may be assignable this
	# way
	return bless \%new_self, ref $self;
}

1;

