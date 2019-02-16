package Bitcoin::Crypto::ExtPublicKey;

use Modern::Perl "2010";
use Moo;

with "Bitcoin::Crypto::Roles::ExtendedKey";

sub _isPrivate { 0 }



1;
