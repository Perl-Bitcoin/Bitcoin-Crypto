package Bitcoin::Crypto::Network;

use Modern::Perl "2010";
use Exporter qw(import);
use Storable qw(dclone);

use Bitcoin::Crypto::Exception;

our @EXPORT_OK = qw(
	set_default_network
	add_network
	find_network
	get_network
	get_default_network
	get_available_networks
	validate_network
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

my %networks = (
	mainnet => {
		name => "Bitcoin Mainnet",
		p2pkh_byte => "\x00",
		p2sh_byte => "\x05",
		segwit_hrp => "bc",
		wif_byte => "\x80",
		extprv_version => 0x0488ade4,
		extpub_version => 0x0488b21e,
	},
	testnet => {
		name => "Bitcoin Testnet",
		p2pkh_byte => "\x6f",
		p2sh_byte => "\xc4",
		segwit_hrp => "tb",
		wif_byte => "\xef",
		extprv_version => 0x04358394,
		extpub_version => 0x043587cf,
	},
);

my $default_network = "mainnet";

# name => required
my %network_keys = qw(
	name 1
	p2pkh_byte 1
	p2sh_byte 0
	segwit_hrp 0
	wif_byte 1
	extprv_version 0
	extpub_version 0
);

my %network_maps;

sub set_default_network
{
	my ($name) = @_;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"trying to set unknown network: $name"
	) unless defined $networks{$name};

	$default_network = $name;
}

sub add_network
{
	my ($name, $args) = @_;
	validate_network($args);
	$networks{$name} = $args;
	_map_networks();
}

sub validate_network
{
	my ($args) = @_;
	for my $el (keys %network_keys) {
		Bitcoin::Crypto::Exception::NetworkConfig->raise(
			"incomplete network configuration: missing key $el"
		) if !defined $args->{$el} && $network_keys{$el};
	}
}

sub find_network
{
	my ($by, $value) = @_;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"network key does not exist: $by"
	) unless defined $network_maps{$by};

	return grep { $value eq $network_maps{$by}{$_} } keys %{$network_maps{$by}};
}

sub get_network
{
	my ($name) = @_;
	$name //= $default_network;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"network key does not exist: $name"
	) unless defined $networks{$name};

	return dclone($networks{$name});
}

sub get_default_network
{
	return get_network();
}

sub get_available_networks
{
	return keys %networks;
}

sub _map_networks
{
	%network_maps = ();
	for my $el (keys %network_keys) {
		my %el_map;
		$network_maps{$el} = \%el_map;
		for my $network (keys %networks) {
			$el_map{$network} = $networks{$network}{$el};
		}
	}
}

_map_networks();

1;

__END__
=head1 NAME

Bitcoin::Crypto::Network - Management tool for cryptocurrency networks

=head1 SYNOPSIS

	use Bitcoin::Crypto::Network qw(:all);

	# by default network is set to bitcoin

	get_default_network()->{name}; # Bitcoin Mainnet

	# by default there are two networks specified
	# these are identified with keys which you can get with

	get_available_networks(); # (mainnet, testnet)

	# you can get other network configuration

	get_network("testnet")->{name}; # Bitcoin Testnet

	# search for the network and get array of keys in return
	# there will be multiple results if your search can be matched
	# by multiple networks

	find_network(name => "Bitcoin Mainnet"); # (mainnet)
	find_network(p2pkh_byte => 0x6f); # (testnet)

	# if you're working with different cryptocurrency you need to add a new network

	# network configuration is important for importing WIF private keys (network
	# recognition), generating addresses and serializing extended keys.
	# Don't use addresses without validating your configuration first!

	# I suggest creating networks by changing values in Bitcoin network
	# this way some of the rather default values will be inherited
	# configuration keys shown below are required

	my $litecoin = get_network("mainnet");
	$litecoin->{name} = "Litecoin Mainnet";
	$litecoin->{p2pkh_byte} = 0x30;
	$litecoin->{wif_byte} = 0xb0;

	add_network(litecoin_mainnet => $litecoin);

	# after you've added your network you can set it as default. This means that
	# all extended keys generated by other means than importing serialized key and
	# all private keys generated by other means than importing WIF will use that
	# configuration.

	set_default_network("litecoin_mainnet");


=head1 DESCRIPTION

This package allows you to manage non-bitcoin cryptocurrencies.
Before you start producing keys and addresses for your favorite crypto
you have to configure it's network first. Right now networks only require
three keys, which are marked with *

	my $network = (
		name => "* human-readable network name",
		p2pkh_byte => "* p2pkh address prefix byte, eg. 0x00",
		p2sh_byte => "p2sh address prefix byte, eg. 0x05",
		segwit_hrp => "segwit native address human readable part, eg. 'bc'",
		wif_byte => "* WIF private key prefix byte, eg. 0x80",
		extprv_version => "version of extended private keys, eg. 0x0488ade4",
		extpub_version => "version of extended public keys, eg. 0x0488b21e",
	);

After you add_network your program will be able to import keys for that
network but all keys created from other sources will be treated as bitcoin.
You need to set_default_network to make all new keys use it. If you use many
networks it might be better to set a network with key's set_network method:

	$priv->set_network("your_network");

Some things to consider:

=over 2

=item * if you don't specify network field for some feature you won't be able to
use it. For example the module will complain if you try to generate segwit address
with custom network without segwit_hrp field set.

=item * it is entirely possible to add a network that already exists. Because of
this, if you don't need bitcoin in your program you can replace existing
networks with custom ones.

=item * get_network functions make clones of network configuration at the time
of creation, so  changing configuration after you've created your keys
may not bring the results you're expecting. You probably shouldn't be doing
this anyway, but if for some reason you need to update your configuration
then you need to either re-create all private and public keys or use set_network
method on them all.

=back

=head1 FUNCTIONS

=head2 set_default_network

	set_default_network("network_key");

Sets the network with $name as default one. All newly created private and public
keys will be bound to this network.
Dies if network doesn't exist

=head2 get_default_network

	$hashref = get_default_network();

Returns deep clone of currently active network's configuration.

=head2 add_network

	add_network(name => $hashref);

Adds network "name" with configuration from $hashref.
Performs $hashref validation (same as validate_network)

=head2 validate_network

	validate_network($hashref);

Validates network configuration under $hashref.
Dies if configuration is invalid.

=head2 find_network

	my @found = find_network(key => $value)

Searches for all networks that have configuration "key" set to $value.
Returns list.
Dies if key doesn't exist.

=head2 get_network

	my $hashref = get_network($name);

Returns network $name configuration. If $name is omitted behaves like
get_default_network().
Dies if network $name doesn't exist.

=head2 get_available_networks

	my @names = get_available_networks();

Returns all available network names.

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=item L<Bitcoin::Crypto::Key::Private>

=back

=cut
