use v5.10;
use warnings;
use Bitcoin::Crypto qw(btc_extprv);
use Bitcoin::Crypto::BIP44;
use Test::More;
use Test::Exception;

sub bip44_get_derived_key_from_mnemonic
{
	my $params = shift;
	my ($mnemonic, $index, $password, $network, $account, $change) =
		@{$params}{qw(mnemonic index password network account change)};

	die "Parameter 'mnemonic' is required"
		unless length $mnemonic;
	die "Parameter 'index' is required"
		unless defined $index;
	$account //= 0;
	$change //= 0;

	# recover from the mnemonic with an optional password
	my $extkey = btc_extprv->from_mnemonic($mnemonic, $password);

	# set a network for newly imported extended key, if specified
	# can be either an instance of Bitcoin::Crypto::Network or an existing network name
	$extkey->set_network($network)
		if defined $network;

	# Construct a bip44-compilant derivation path
	my $bip44 = Bitcoin::Crypto::BIP44->new(
		coin_type => $extkey, # can be a key instance, a network instance or just an integer
		account => $account,
		change => $change,
		index => $index
	);

	# derive the key and return the basic key
	# returned key is of type Bitcoin::Crypto::Key::Private
	# and have a proper network field set (to produce valid WIFs and addresses)
	return $extkey->derive_key($bip44)->get_basic_key;
}

my $key = bip44_get_derived_key_from_mnemonic(
	{
		mnemonic =>
			"bachelor taxi wrong egg range weasel submit bless clutch liberty hip cloth guitar debate vibrant",
		password => "qwerty",
		network => "bitcoin",
		account => 0,
		change => 0,
		index => 7,
	}
);
is $key->to_wif(), "L2Xpy9ST9bT9531yAjjLfXGxeXQJfnpVsvnuo4eRwBzDFNpeTzR7";

done_testing;

__END__

=head1 BIP44 implementation example

This example implements a single perl function C<bip44_get_derived_key_from_mnemonic>. This function performs an extended key derivation with paths specified in bip44 document. Base key is taken from mnemonic code with optional password. A resulting scalar variable is a basic private key instance, which can be used for message signing, verification and address generation.

See the example code for step-by-step explanations in comments.
