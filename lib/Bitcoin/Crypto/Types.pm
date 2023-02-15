package Bitcoin::Crypto::Types;

use v5.10;
use strict;
use warnings;

use Type::Library -extends => [
	qw(
		Types::Standard
		Types::Common::Numeric
		Types::Common::String
	)
];
use Type::Coercion;

# make sure Math::BigInt is properly loaded - this module loads it
use Bitcoin::Crypto::Helpers;
use Bitcoin::Crypto::Constants;

__PACKAGE__->add_type(
	name => 'BIP44Purpose',
	parent => Maybe [
		Enum->of(
			Bitcoin::Crypto::Constants::bip44_purpose,
			Bitcoin::Crypto::Constants::bip44_compat_purpose,
			Bitcoin::Crypto::Constants::bip44_segwit_purpose
		)
	],
);

my $formatstr = __PACKAGE__->add_type(
	name => 'FormatStr',
	parent => Enum->of(
		'bytes',
		'hex',
		'base58',
	)
);

my $formatdesc = __PACKAGE__->add_type(
	name => 'FormatDesc',
	parent => Tuple->of(
		$formatstr,
		Str,
	)
);

my $bytestr = __PACKAGE__->add_type(
	name => 'ByteStr',
	parent => Str,

	constraint => qq{ (grep { ord > 255 } split //) == 0 },

	inline => sub {
		my $varname = pop;

		return (undef, qq{ (grep { ord > 255 } split //, $varname) == 0 });
	},

	message => sub {
		return 'Value is not a bytestring';
	},
);

$bytestr->coercion->add_type_coercions(
	$formatdesc, q{ Bitcoin::Crypto::Helpers::parse_formatdesc($_) }
);

my $script = __PACKAGE__->add_type(
	name => 'BitcoinScript',
	parent => InstanceOf->of('Bitcoin::Crypto::Script'),
);

$script->coercion->add_type_coercions(
	$bytestr->coercibles, q{ Bitcoin::Crypto::Script->from_serialized($_) }
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

__PACKAGE__->make_immutable;

1;

# Internal use only

