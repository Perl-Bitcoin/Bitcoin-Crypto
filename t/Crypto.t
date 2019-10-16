use strict;
use warnings;

use Test::More;

BEGIN { use_ok('Bitcoin::Crypto', qw(version))};

like(version(), qr/\d+\.\d+/, "version string ok");

done_testing;
