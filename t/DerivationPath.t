use Test2::V0;
use Bitcoin::Crypto::DerivationPath;

my $path = Bitcoin::Crypto::DerivationPath->from_string(q{m/1/2'/3});
is !!$path->private, !!1, 'private flag ok';
is $path->path, [1, 2 + 2**31, 3], 'path ok';
is $path->get_path_hardened, [[1, !!0], [2, !!1], [3, !!0]], 'path_hardened ok';
is $path->as_string, q{m/1/2'/3}, 'as_string ok';
is "$path", q{m/1/2'/3}, 'automatic stringification ok';

ok $path->does('Bitcoin::Crypto::Role::WithDerivationPath'), 'does proper role ok';
is $path->get_derivation_path, $path, 'get_derivation_path ok';

done_testing;

