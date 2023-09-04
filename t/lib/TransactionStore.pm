package TransactionStore;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;

use Bitcoin::Crypto qw(btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);

my %utxos = (
	'a34b7271d2add50bb6eaeaaaffaebe33bf4e3fe0454ca5d46ab64e6dbbbf1174;0' => {
		locking_script => [P2WPKH => 'bc1q7x7ua3s92k8gayvl8ltlqympxf53z075z486r2'],
		value => 198959,
	},
);

sub get_utxo
{
	my ($txid, $index) = @_;

	my $readable_txid = to_format [hex => $txid];
	if ($utxos{"$readable_txid;$index"}) {
		my $output = delete $utxos{"$readable_txid;$index"};
		return btc_utxo->new(
			txid => $txid,
			output_index => $index,
			output => $output,
		);
	}

	return undef;
}

btc_utxo->set_loader(\&get_utxo);

1;

