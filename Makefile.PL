use 5.010001;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => 'Bitcoin::Crypto',
	VERSION_FROM => 'lib/Bitcoin/Crypto.pm',
	MIN_PERL_VERSION => '5.010001',

	TEST_REQUIRES => {
		'Test::More' => '0.88',
		'Test::Exception' => 0,
	},
	PREREQ_PM => {
		'Math::BigInt' => '1.999808',
		'Moo' => '2.003004',
		'Type::Tiny' => '1.004000',
		'CryptX' => '0.062',
		'Bitcoin::BIP39' => '0.002',
		'namespace::clean' => '0.27',
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
