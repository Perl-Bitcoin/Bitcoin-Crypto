use Test2::V0;
use Bitcoin::Crypto qw(btc_psbt btc_transaction);
use Bitcoin::Crypto::Util qw(to_format pack_compactsize);
use Bitcoin::Crypto::Constants qw(:psbt :transaction);

my $minimal_tx = btc_transaction->new(version => 2)
	->add_input(
		utxo => [[hex => '1d39012ae4839360ade708a32c64548b0ffde92421bc3348eaf07a55ad87f651'], 0],
		sequence_no => RBF_SEQUENCE_NO_THRESHOLD,
	)
	->add_output(
		locking_script => [address => 'bc1qcmg5at52pevn4elntrefy40j5wfjpypsxvuamf'],
		value => 216168,
	);

my $minimal_tx_hex = to_format [hex => $minimal_tx->to_serialized];
my $minimal_tx_hex_len = to_format [hex => pack_compactsize(length($minimal_tx_hex) / 2)];

subtest 'should disallow maps without a final separator' => sub {
	my $erroneous = (to_format [hex => PSBT_MAGIC])
		. "0100${minimal_tx_hex_len}${minimal_tx_hex}00"
		. "00"
		. "01000152";    # NOTE: no final zero here

	my $ex = dies { btc_psbt->from_serialized([hex => $erroneous]); };
	isa_ok $ex, 'Bitcoin::Crypto::Exception::PSBT';
	like $ex, qr{serialized map data is corrupted}, 'exception full ok';
};

done_testing;

