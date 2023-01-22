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
use Bitcoin::Crypto::Constants;

__PACKAGE__->add_type(
	name => 'BIP44Purpose',
	parent => Maybe [Enum->of(44, 49, 84)],
);

__PACKAGE__->add_type(
	name => 'IntMaxBits',
	parent => PositiveOrZeroInt,

	constraint_generator => sub {
		my $bits = assert_PositiveInt(shift);

		# for same bits as system, no need for special constraint
		return sub { 1 }
			if Bitcoin::Crypto::Constants::ivsize * 8 == $bits;

		# can't handle
		die 'IntMaxBits only handles up to ' . (Bitcoin::Crypto::Constants::ivsize * 8) . ' bits on this system'
			if Bitcoin::Crypto::Constants::ivsize * 8 < $bits;

		my $limit = 1 << $bits;
		return sub {
			return $_ < $limit;
		};
	},

	inline_generator => sub {
		my $bits = shift;

		return sub {
			# for same bits as system, no need for special constraint
			return (undef, qq{ 1 })
				if Bitcoin::Crypto::Constants::ivsize * 8 == $bits;

			my $varname = pop;

			my $limit = 1 << $bits;
			return (undef, qq{ $varname < $limit });
		}
	},

	message => sub {
		my $bits = shift;
		return "Value does not fit in $bits bits";
	},
);

1;

# Internal use only

