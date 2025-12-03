package Bitcoin::Crypto::Role::WithDerivationPath;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;

requires qw(get_derivation_path);

1;

