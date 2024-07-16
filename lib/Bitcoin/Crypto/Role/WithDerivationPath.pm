package Bitcoin::Crypto::Role::WithDerivationPath;

use v5.10;
use strict;
use warnings;

use Moo::Role;

requires qw(get_derivation_path);

1;

