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

my $derivation_path = __PACKAGE__->add_type(
	name => 'DerivationPath',
	parent => InstanceOf->of('Bitcoin::Crypto::DerivationPath'),
);

$derivation_path->coercion->add_type_coercions(
	Str, q{ require Bitcoin::Crypto::DerivationPath; Bitcoin::Crypto::DerivationPath->from_string($_) },
	ConsumerOf->of('Bitcoin::Crypto::Role::WithDerivationPath'), q{ $_->get_derivation_path },
);

__PACKAGE__->make_immutable;

1;

__END__
=head1 NAME

Bitcoin::Crypto::Types - Bitcoin-specific data types

=head1 SYNOPSIS

	use Bitcoin::Crypto::Types qw(
		BIP44Purpose
		FormatStr
		FormatDesc
		ByteStr
		ScriptType
		ScriptDesc
		BitcoinScript
		PSBTMapType
		PSBTFieldType
		IntMaxBits
		SatoshiAmount
		DerivationPath
	);

=head1 DESCRIPTION

This module is a L<Type::Tiny> library for types which are either specific for
Bitcoin or are used by Bitcoin::Crypto to implement its routines.

=head1 AVAILABLE TYPES

=head2 BIP44Purpose

An integer with one of the available purpose numbers for BIP44, like C<44>.

=head2 FormatStr

A string with one of the available format names, like C<hex>.

=head2 FormatDesc

An array reference with exactly two elements, where the first one is
L</FormatStr> and the second one is a string with the data encoded in that
format.

=head2 ByteStr

A string where each character is 8 bit. Can be coerced from L</FormatDesc>.

=head2 ScriptType

A string with one of the available script type names, like C<P2WPKH>.

=head2 ScriptDesc

An array reference with exactly two elements, where the first one is
L</ScriptType> or a string C<address>, and the second one is defined data
specific for that script type.

=head2 BitcoinScript

An instance of L<Bitcoin::Crypto::Script>. Can be coerced from L</ScriptDesc>
or L</ByteStr> (or any of its coercion types).

=head2 PSBTMapType

A string with one of the available PSBT map type names, like C<global>.

=head2 PSBTFieldType

An instance of L<Bitcoin::Crypto::PSBT::FieldType>. Can be coerced from a
string name of the PSBT field, or from an array reference of two values, where
the first one is L</PSBTMapType> and the second one is a positive integer with
field code.

=head2 IntMaxBits

A non-negative integer which must be small enough to be representable with the
specified number of bits (parametrizable).

=head2 SatoshiAmount

A non-negative integer, represented as L<Math::BigInt> object. Can be coerced
from an integer or from a string.

=head2 DerivationPath

An instance of L<Bitcoin::Crypto::DerivationPath>. Can be coerced from a string
or a class consuming C<Bitcoin::Crypto::Role::WithDerivationPath>.

=head1 SEE ALSO

L<Type::Library>

