use 5.010000;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => 'Bitcoin::Crypto',
	VERSION_FROM => 'lib/Bitcoin/Crypto.pm',
	MIN_PERL_VERSION => '5.010',

	CONFIGURE_REQUIRES => {
		'ExtUtils::MakeMaker' => '>=6.55_03',
	},
	BUILD_REQUIRES => {
		'ExtUtils::MakeMaker' => '>=6.55_03',
	},
	TEST_REQUIRES => {
		'Test::More' => '>= 0.88',
		'Test::Exception' => 0,
	},
	PREREQ_PM => {
		'Modern::Perl' => '>= 1.20181021',
		'Math::EllipticCurve::Prime' => '>= 0.003',
		'Math::BigInt' => '>= 1.999818',
		'Math::BigInt::GMP' => '>= 1.6006',
		'Moo' => '>= 2.004000',
		'Type::Tiny' => '>= 1.010001',
		'CryptX' => '>= 0.068',
		'Bitcoin::BIP39' => '>= 0.002',
		'Try::Tiny' => '>= 0.30',
		'Throwable' => '>= 0.2',
	},

	META_MERGE => {
		resources => {
			license => 'https://dev.perl.org/licenses',
			homepage => 'https://metacpan.org/release/Bitcoin-Crypto',
			bugtracker => 'https://github.com/brtastic/perl-bitcoin-crypto/issues',
			repository => 'https://github.com/brtastic/perl-bitcoin-crypto',
		},
	},

	ABSTRACT_FROM => 'lib/Bitcoin/Crypto.pm',
	AUTHOR => 'Bartosz Jarzyna <brtastic.dev@gmail.com>',
	LICENSE => 'perl',
);
