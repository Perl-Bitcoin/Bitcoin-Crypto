use strict;
use warnings;

use Test::More tests => 2;

BEGIN { use_ok('Bitcoin::Crypto', qw(version))};

like(version(), qr/\d+\.\d+/, "version string ok");