package Bitcoin::Crypto::Role::WithDerivationPath;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard, -role;

requires qw(get_derivation_path);

1;

