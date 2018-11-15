use strict;
use warnings;

use Test::More tests => 3;

BEGIN { use_ok('Bitcoin::Crypto::Config') };

ok(defined *config{HASH}, "config exported by default");

is(scalar keys %config, 6, "config has correct amount of entries");
