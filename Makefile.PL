use 5.010000;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Bitcoin::Crypto',
    VERSION_FROM      => 'lib/Bitcoin/Crypto.pm',
    PREREQ_PM         => {
        Modern::Perl => 1.20181021,
        Moo => 2.003004,
        MooX::Types::MooseLike => 0.29,
        CryptX => 0.062,
        Crypt::RIPEMD160 => 0.06,
        Bitcoin::BIP39 => 0.002,
        Try::Tiny => 0.30
    },
    ABSTRACT_FROM     => 'lib/Bitcoin/Crypto.pm',
    AUTHOR            => 'Bartosz Jarzyna <brtastic.dev@gmail.com>',
    LICENSE           => 'perl',
);
