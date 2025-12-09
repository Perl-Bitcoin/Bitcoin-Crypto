use Test2::V0;

skip_all 'This test requires Test::Pod::LinkCheck::Lite'
	unless eval { require Test::Pod::LinkCheck::Lite; 1 };

my $t = Test::Pod::LinkCheck::Lite->new;
$t->all_pod_files_ok('lib');

done_testing;

