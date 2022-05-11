package Bitcoin::Crypto::Types;

use v5.10;
use strict;
use warnings;
use Type::Library -base;
use Type::Coercion;
use Types::Common::Numeric qw(assert_PositiveInt);
use Types::Standard qw(Int InstanceOf);

BEGIN {
	require Math::BigInt;

	# Version 1.6003 of optional GMP is required for the from_bytes / to_bytes implementations
	if (eval { require Math::BigInt::GMP; Math::BigInt::GMP->VERSION('1.6003'); 1 }) {
		Math::BigInt->import(try => 'GMP,LTM');
	}
	else {
		Math::BigInt->import(try => 'LTM');
	}
}

__PACKAGE__->add_type(
	name => "IntMaxBits",
	parent => InstanceOf->of("Math::BigInt"),

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

