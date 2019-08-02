use 5.010000;
use ExtUtils::MakeMaker;
use Alien::GMP;

WriteMakefile(
	NAME              => 'Bitcoin::Crypto',
	VERSION_FROM      => 'lib/Bitcoin/Crypto.pm',
	CONFIGURE_REQUIRES => {
		Alien::GMP => 1.14,
	},
	CCFLAGS           => Alien::GMP->cflags . " $Config{ccflags}",
	LIBS              => [ Alien::GMP->libs ],
	PREREQ_PM         => {
		Modern::Perl => 1.20181021,
		Math::BigInt => 1.999816,
		Math::BigInt::GMP => 1.6006,
		Moo => 2.003004,
		MooX::Types::MooseLike => 0.29,
		CryptX => 0.062,
		Bitcoin::BIP39 => 0.002,
		Try::Tiny => 0.30,
		Digest::SHA => 6.02,
		Math::EllipticCurve::Prime => 0.003,
		PBKDF2::Tiny => 0.005,
	},
	ABSTRACT_FROM     => 'lib/Bitcoin/Crypto.pm',
	AUTHOR            => 'Bartosz Jarzyna <brtastic.dev@gmail.com>',
	LICENSE           => 'perl',
);