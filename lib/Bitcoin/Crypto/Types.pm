package Bitcoin::Crypto::Types;

use v5.10;
use strict;
use warnings;

use Type::Library -base;
use Type::Coercion;
use Types::Common -types;

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
		'base64',
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
	$formatdesc, q{ Bitcoin::Crypto::Helpers::parse_formatdesc(@{$_}) }
);

my $scripttype = __PACKAGE__->add_type(
	name => 'ScriptType',
	parent => Enum->of(qw(P2PK P2PKH P2SH P2MS P2WPKH P2WSH P2TR NULLDATA))
);

my $scriptdesc = __PACKAGE__->add_type(
	name => 'ScriptDesc',
	parent => Tuple->of(
		$scripttype | Enum->of(qw(address)),
		Defined,
	)
);

my $script = __PACKAGE__->add_type(
	name => 'BitcoinScript',
	parent => InstanceOf->of('Bitcoin::Crypto::Script'),
);

$script->coercion->add_type_coercions(
	$scriptdesc, q{ require Bitcoin::Crypto::Script; Bitcoin::Crypto::Script->from_standard(@$_) },
	$bytestr->coercibles, q{ require Bitcoin::Crypto::Script; Bitcoin::Crypto::Script->from_serialized($_) },
);

my $psbt_map_type = __PACKAGE__->add_type(
	name => 'PSBTMapType',
	parent => Enum->of(
		Bitcoin::Crypto::Constants::psbt_global_map,
		Bitcoin::Crypto::Constants::psbt_input_map,
		Bitcoin::Crypto::Constants::psbt_output_map,
	),
);

my $psbt_field_type = __PACKAGE__->add_type(
	name => 'PSBTFieldType',
	parent => InstanceOf->of('Bitcoin::Crypto::PSBT::FieldType'),
);

$psbt_field_type->coercion->add_type_coercions(
	Tuple->of($psbt_map_type, PositiveOrZeroInt),
	q{ require Bitcoin::Crypto::PSBT::FieldType; Bitcoin::Crypto::PSBT::FieldType->get_field_by_code(@$_) },
	Str, q{ require Bitcoin::Crypto::PSBT::FieldType; Bitcoin::Crypto::PSBT::FieldType->get_field_by_name($_) },
);

__PACKAGE__->add_type(
	name => 'IntMaxBits',
	parent => PositiveOrZeroInt,

	constraint_generator => sub {
		my $bits = PositiveInt->assert_valid(shift);

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

my $satoshi_amount = __PACKAGE__->add_type(
	name => 'SatoshiAmount',
	parent => InstanceOf->of('Math::BigInt')->where(q{$_ >= 0}),
);

$satoshi_amount->coercion->add_type_coercions(
	Int | Str, q{ Math::BigInt->new($_) },
);

__PACKAGE__->make_immutable;

1;

# This module is mostly used internally, but it can be used from outside for
# bitcoin-specific types like BIP44Purpose.

