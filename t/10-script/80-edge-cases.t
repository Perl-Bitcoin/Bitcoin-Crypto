use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto qw(btc_script);

subtest 'should detect P2PKH / P2SH mismatch' => sub {
	throws_ok {
		btc_script->from_standard(P2PKH => '3HDtyBHZ4111BFtUBY2SA4eXJQxifmaTYw');
	} 'Bitcoin::Crypto::Exception::NetworkCheck';

	throws_ok {
		btc_script->from_standard(P2SH => '1AshirGYwnrFsN82DpV83NDfQpRJMuXxLQ');
	} 'Bitcoin::Crypto::Exception::NetworkCheck';
};

subtest 'should detect P2WPKH / P2WSH mismatch' => sub {
	throws_ok {
		btc_script->from_standard(P2WPKH => 'bc1qxrv57xwn050dht30kt9msenkqf67rh0cjcurhukznucjwk63xm3skajjcc');
	} 'Bitcoin::Crypto::Exception::SegwitProgram';

	throws_ok {
		btc_script->from_standard(P2WSH => 'bc1q73vqlq8ptpjhd4pnghqq0gvn3nqh4tn00utypf');
	} 'Bitcoin::Crypto::Exception::SegwitProgram';
};

subtest 'should detect P2WPKH from different network' => sub {
	throws_ok {
		btc_script->from_standard(P2WPKH => 'tb1q26jy9d4vkfqezh6hm7qp7txvk8nggkwv2y72x0');
	} 'Bitcoin::Crypto::Exception::NetworkCheck';
};

subtest 'should not mistake P2WSH for P2TR' => sub {
	throws_ok {
		btc_script->from_standard(P2TR => 'bc1qxrv57xwn050dht30kt9msenkqf67rh0cjcurhukznucjwk63xm3skajjcc');
	} 'Bitcoin::Crypto::Exception::SegwitProgram';
};

done_testing;

