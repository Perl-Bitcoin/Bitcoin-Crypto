use v5.10;
use strict;
use warnings;

{

	package Wallet;

	use Moo;
	use Mooish::AttributeBuilder;

	use Bitcoin::Crypto qw(btc_extprv);
	use Bitcoin::Crypto::Network;
	use Storable;
	use Try::Tiny;

	use constant FILENAME => '.wallet.state';

	# not stored in object to avoid being serialized
	my %master_keys;

	has option 'mnemonic_file' => (
		writer => 1,
	);

	has option 'mnemonic_password' => (
		writer => 1,
	);

	has param 'network' => (
		writer => 1,
		default => 'bitcoin',
	);

	has param 'account' => (
		writer => 1,
		default => 0,
	);

	has param 'last_key' => (
		writer => 1,
		default => 0,
	);

	sub inc
	{
		my ($self) = @_;
		$self->set_last_key($self->last_key + 1);
	}

	sub inc_account
	{
		my ($self) = @_;
		$self->set_account($self->account + 1);
	}

	sub master_key
	{
		my ($self) = @_;

		return $master_keys{$self};
	}

	sub save
	{
		my ($self) = @_;
		store $self, $self->FILENAME;
	}

	sub restore
	{
		my ($class) = @_;

		my $self;
		try {
			$self = retrieve $class->FILENAME;
		}
		catch {
			$self = $class->new;
		};

		$self->initialize;
		return $self;
	}

	sub initialize
	{
		my ($self) = @_;

		if (!$self->has_mnemonic_file) {
			say 'No file containing mnemonic was specified.';
			print 'Path to file: ';

			my $path = readline STDIN;
			chomp $path;
			$self->set_mnemonic_file($path);
		}

		if (!$self->has_mnemonic_password) {
			say 'No mnemonic password was specified.';
			print 'Password (leave empty if none): ';

			my $pass = readline STDIN;
			chomp $pass;
			$self->set_mnemonic_password($pass);
		}

		my $words = do {
			open my $fh, '<', $self->mnemonic_file
				or die "couldn't open " . $self->mnemonic_file . ": $!";

			my $mnemonic = readline $fh;
			chomp $mnemonic;
			$mnemonic;
		};

		Bitcoin::Crypto::Network->get($self->network)->set_default;
		$master_keys{$self} = btc_extprv->from_mnemonic($words, $self->mnemonic_password);
	}

	sub get_key
	{
		my ($self, $account, $index) = @_;

		return $self->master_key->derive_key_bip44(
			purpose => 84,
			account => $account // $self->account,
			index => $index // $self->last_key
		)->get_basic_key;
	}
}

my $wallet = Wallet->restore;
my $arg = shift;

if (!$arg || $arg eq 'last') {
	say 'Getting last used address';
}
elsif ($arg eq 'new') {
	say 'Getting new address';
	$wallet->inc;
}
elsif ($arg eq 'new_account') {
	say 'Getting new account';
	$wallet->inc_account;
	$wallet->set_last_key(0);
}
elsif ($arg eq 'switch') {
	my $network = $wallet->network;
	my @available = qw(bitcoin bitcoin_testnet);
	my ($new) = grep { $_ ne $network } @available;
	say "Switching network to $new";
	$wallet->set_network($new);
	$wallet->initialize;
}
else {
	die 'invalid argument';
}

my $pkey = $wallet->get_key;
say '(account ' . $wallet->account . ', index ' . $wallet->last_key . ')';
say 'address: ' . $pkey->get_public_key->get_address;
say 'priv: ' . $pkey->to_wif;

$wallet->save;

__END__

=head1 Hierarchical Deterministic wallet with persistence example

This example shows how to implement a wallet which follows HD wallet rules. It
is quite incomplete, but provides a solid base for custom features.

