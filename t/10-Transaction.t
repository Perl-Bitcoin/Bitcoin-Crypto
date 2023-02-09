use v5.10;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use Bitcoin::Crypto::Util qw(format_as);

BEGIN { use_ok('Bitcoin::Crypto::Transaction') }

subtest 'should serialize transactions' => sub {
	my $tx = Bitcoin::Crypto::Transaction->new;
	my $tx_hash = '35a5c65c26549079d8369a2d445a79e0c195f4651495eb6f360a3e8766e30757';
	my $expected = '010000000001017411bfbb6d4eb66ad4a54c45e03f4ebf33beaeffaaeaeab60bd5add271724ba30000000000ffffffff026ef80200000000001976a914cf0d26e32df5b94905a7f372e4db12132be29f8e88ac140f00000000000016001428487e88a2870efdd700526a8904cfd78293a6780247304402201c57d633dea588b7c7e5b42e3fd72b7131c154293032dde60e380844403c2402022075a9eb1690de8b2dde0d45d643bcb64ad0c1782ca4cf1a9ca37c0b92e70501330121023a95ab5d95fd2ca4a849e66124e55a549a6e7573dfed0b7356f74ac3862f390100000000';

	$tx->add_input(
		transaction_hash => [hex => 'a34b7271d2add50bb6eaeaaaffaebe33bf4e3fe0454ca5d46ab64e6dbbbf1174'],
		transaction_output_index => 0,
		signature_script => '',
		value => 198959,
	);

	$tx->add_output(
		value => 194670,
		locking_script => Bitcoin::Crypto::Script->new
			->add('OP_DUP')
			->add('OP_HASH160')
			->push([hex => 'cf0d26e32df5b94905a7f372e4db12132be29f8e'])
			->add('OP_EQUALVERIFY')
			->add('OP_CHECKSIG')
	);

	$tx->add_output(
		value => 3860,
		locking_script => Bitcoin::Crypto::Script->new
			->push(chr 0)
			->push([hex => '28487e88a2870efdd700526a8904cfd78293a678'])
	);

	$tx->add_witness(
		[hex => '304402201c57d633dea588b7c7e5b42e3fd72b7131c154293032dde60e380844403c2402022075a9eb1690de8b2dde0d45d643bcb64ad0c1782ca4cf1a9ca37c0b92e705013301'],
		[hex => '023a95ab5d95fd2ca4a849e66124e55a549a6e7573dfed0b7356f74ac3862f3901']
	);

	is format_as [hex => $tx->to_serialized_witness], $expected, 'serialized ok';
	is format_as [hex => $tx->get_hash], $tx_hash, 'hash ok';
	is $tx->fee, 429, 'fee ok';
};

done_testing;

