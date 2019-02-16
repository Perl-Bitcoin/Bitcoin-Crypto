use strict;
use warnings;

use Test::More tests => 7;
use Try::Tiny;

BEGIN { use_ok('Bitcoin::Crypto::Types', qw(:all)) };

package TestMoo {
    use Moo;
    use Bitcoin::Crypto::Types qw(:all);

    has "t1" => (
        is => "ro",
        isa => IntMaxBits[5]
    );

    has "t2" => (
        is => "ro",
        isa => StrExactLength[2]
    );
}

try {
    TestMoo->new(t1 => 33);
    fail("types pass for invalid data");
} catch {
    pass("types fail for invalid data");
};
try {
    TestMoo->new(t1 => 32);
    fail("types pass for invalid data");
} catch {
    pass("types fail for invalid data");
};
try {
    TestMoo->new(t1 => -1);
    fail("types pass for invalid data");
} catch {
    pass("types fail for invalid data");
};
try {
    TestMoo->new(t2 => "a");
    fail("types pass for invalid data");
} catch {
    pass("types fail for invalid data");
};
try {
    TestMoo->new(t2 => "aaa");
    fail("types pass for invalid data");
} catch {
    pass("types fail for invalid data");
};

try {
    TestMoo->new(t1 => 25);
    TestMoo->new(t1 => 31);
    TestMoo->new(t2 => "aa");
    pass("types pass for valid data");
} catch {
    fail("types fail for invalid data");
};
