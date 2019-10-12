use strict;
use warnings;

use Test::More tests => 2;

BEGIN { use_ok('Bitcoin::Crypto::Config') };

ok(defined *config{HASH}, "config exported by default");
