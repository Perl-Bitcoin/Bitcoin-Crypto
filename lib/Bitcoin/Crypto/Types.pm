package Bitcoin::Crypto::Types;

use v5.10;
use strict;
use warnings;

use Type::Library -extends => [ qw(
	Types::Standard
	Types::Common::Numeric
	Types::Common::String
) ];
use Type::Coercion;

# make sure Math::BigInt is properly loaded - this module loads it
use Bitcoin::Crypto::Helpers;

__PACKAGE__->add_type(
	name => 'BIP44Purpose',
	parent => Maybe [Enum->of(44, 49, 84)],
);

__PACKAGE__->add_type(
	name => 'IntMaxBits',
	parent => InstanceOf->of('Math::BigInt'),

	constraint_generator => sub {
		my $bits = assert_PositiveInt(shift) - 1;
		my $limit = Math::BigInt->new(2)->blsft($bits);
		return sub {
			return $_->bge(0) && $_->blt($limit);
		};
	},

	coercion_generator => sub {
		return Type::Coercion->new(
			type_coercion_map => [
				Int, q{Math::BigInt->new($_)},
			],
		);
	},

	message => sub {
		my $bits = shift;
		return "Value does not fit in $bits bits";
	},
);

1;

# Internal use only

