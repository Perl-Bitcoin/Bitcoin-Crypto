package Bitcoin::Crypto::Network;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Object HashRef CodeRef Str StrLength Int Maybe);

use namespace::clean;

my %networks;
my $default_network;

has param 'id' => (
	isa => Str,
);

has param 'name' => (
	isa => Str,
);

has param 'p2pkh_byte' => (
	isa => StrLength [1, 1],
);

has param 'wif_byte' => (
	isa => StrLength [1, 1],
);

has param 'p2sh_byte' => (
	isa => StrLength [1, 1],
	required => 0,
);

has param 'segwit_hrp' => (
	isa => Str,
	required => 0,
);

has param 'extprv_version' => (
	isa => Int,
	required => 0,
);

has param 'extpub_version' => (
	isa => Int,
	required => 0,
);

has param 'extprv_compat_version' => (
	isa => Int,
	required => 0,
);

has param 'extpub_compat_version' => (
	isa => Int,
	required => 0,
);

has param 'extprv_segwit_version' => (
	isa => Int,
	required => 0,
);

has param 'extpub_segwit_version' => (
	isa => Int,
	required => 0,
);

has param 'bip44_coin' => (
	isa => Int,
	required => 0,
);

signature_for register => (
	method => !!1,
	positional => [HashRef, {slurpy => !!1}],
);

sub register
{
	my ($self, $config) = @_;

	if (!ref $self) {
		$self = $self->new($config);
	}

	$networks{$self->id} = $self;
	return $self;
}

signature_for set_default => (
	method => Object,
	positional => [],
);

sub set_default
{
	my ($self) = @_;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'the network needs to be registered before becoming the default one'
	) unless defined $networks{$self->id};

	$default_network = $self->id;
	return $self;
}

signature_for supports_segwit => (
	method => Object,
	positional => [],
);

sub supports_segwit
{
	my ($self) = @_;

	return defined $self->segwit_hrp;
}

signature_for find => (
	method => Str,
	positional => [Maybe [CodeRef], {default => undef}],
);

sub find
{
	my ($class, $sub) = @_;

	return keys %networks
		unless defined $sub;

	return grep { $sub->($networks{$_}) } keys %networks;
}

signature_for get => (
	method => Str,
	positional => [Str, {default => sub { $default_network }}],
);

sub get
{
	my ($class, $id) = @_;

	my $network = $networks{$id};
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"network $id is not registered"
	) unless defined $network;

	return $network;
}

### PREDEFINED NETWORKS SECTION
# When adding a network, make sure to:
# - code in valid constants of the network below
# - provide resources that will confirm these constant values (in the merge request)
# - add your network to the POD documentation below
# - add your network to test file 17-predefined-networks.t

### BITCOIN

__PACKAGE__->register(
	id => 'bitcoin',
	name => 'Bitcoin Mainnet',
	p2pkh_byte => "\x00",
	p2sh_byte => "\x05",
	wif_byte => "\x80",
	segwit_hrp => 'bc',

	extprv_version => 0x0488ade4,
	extpub_version => 0x0488b21e,

	extprv_compat_version => 0x049d7878,
	extpub_compat_version => 0x049d7cb2,

	extprv_segwit_version => 0x04b2430c,
	extpub_segwit_version => 0x04b24746,

	bip44_coin => 0,
)->set_default;

__PACKAGE__->register(
	id => 'bitcoin_testnet',
	name => 'Bitcoin Testnet',
	p2pkh_byte => "\x6f",
	p2sh_byte => "\xc4",
	wif_byte => "\xef",
	segwit_hrp => 'tb',

	extprv_version => 0x04358394,
	extpub_version => 0x043587cf,

	extprv_compat_version => 0x044a4e28,
	extpub_compat_version => 0x044a5262,

	extprv_segwit_version => 0x045f18bc,
	extpub_segwit_version => 0x045f1cf6,

	bip44_coin => 1,
);

### DOGECOIN

__PACKAGE__->register(
	id => 'dogecoin',
	name => 'Dogecoin Mainnet',
	p2pkh_byte => "\x1e",
	p2sh_byte => "\x16",
	wif_byte => "\x9e",

	extprv_version => 0x02fac398,
	extpub_version => 0x02facafd,

	bip44_coin => 3,
);

__PACKAGE__->register(
	id => 'dogecoin_testnet',
	name => 'Dogecoin Testnet',
	p2pkh_byte => "\x71",
	p2sh_byte => "\xc4",
	wif_byte => "\xf1",

	extprv_version => 0x04358394,
	extpub_version => 0x043587cf,

	bip44_coin => 1,
);

1;

__END__

=head1 NAME

Bitcoin::Crypto::Network - Network management class

=head1 SYNOPSIS

	use Bitcoin::Crypto::Network;

	# the default network is Bitcoin Mainnet
	# get() without arguments returns default network

	Bitcoin::Crypto::Network->get->name; # 'Bitcoin Mainnet'

	# by default there are two networks specified
	# find() without arguments returns a list of all network ids

	Bitcoin::Crypto::Network->find; # list of strings

	# you can get full network configuration with get() using network id

	Bitcoin::Crypto::Network->get('bitcoin_testnet')->name; # 'Bitcoin Testnet'

	# search for network and get array of keys in return
	# there will be multiple results if your search is matched
	# by multiple networks

	Bitcoin::Crypto::Network->find(sub { shift->name eq 'Bitcoin Mainnet' }); # ('bitcoin')
	Bitcoin::Crypto::Network->find(sub { shift->p2pkh_byte eq "\x6f" }); # ('bitcoin_testnet')

	# if you're working with cryptocurrency other than Bitcoin you need to add a new network

	# network configuration is important for importing WIF private keys (network
	# recognition), generating addresses and serializing extended keys.
	# It may also hold other data specific to a network

	# register() can be used to create a network

	my $litecoin = Bitcoin::Crypto::Network->register(
		id => 'litecoin',
		name => 'Litecoin Mainnet',
		p2pkh_byte => "\x30",
		wif_byte => "\xb0",
	);

	# after you've added a new network you can set it as a default. This means that
	# all extended keys generated by other means than importing serialized key and
	# all private keys generated by other means than importing WIF / extended keys
	# will use that configuration.

	$litecoin->set_default;


=head1 DESCRIPTION

This package allows you to manage non-bitcoin cryptocurrencies or chains other
than mainnet. Before you start producing keys and addresses for your favorite
crypto you have to configure its network first.

=head1 PREDEFINED NETWORKS

Here is a list of networks that are already defined and can be used out of the box.

If you want to see more predefined networks added and you're willing to make
some research to find out the correct values for the configuration fields,
consider opening a pull request on Github.

=head2 Bitcoin Mainnet

defined with id: C<bitcoin>

=head2 Bitcoin Testnet

defined with id: C<bitcoin_testnet>

=head2 Dogecoin Mainnet

defined with id: C<dogecoin>

=head2 Dogecoin Testnet

defined with id: C<dogecoin_testnet>

=head1 CONFIGURATION

Configuration fields marked with C<(*)> are required. The rest are optional,
but some functions of the system will refuse to work without them.

	my %config = (
		id             => "(*) string identifier for the network, eg. 'bitcoin'",
		name           => "(*) human-readable network name, eg. 'Bitcoin Mainnet'",
		p2pkh_byte     => "(*) p2pkh address prefix byte, eg. 0x00",
		wif_byte       => "(*) WIF private key prefix byte, eg. 0x80",
		p2sh_byte      => "p2sh address prefix byte, eg. 0x05",
		segwit_hrp     => "segwit native address human readable part, eg. 'bc'",

		extprv_version        => "version prefix of serialized extended private keys, eg. 0x0488ade4",
		extpub_version        => "version prefix of serialized extended public keys, eg. 0x0488b21e",
		extprv_compat_version => "same as extprv_version, but for BIP49",
		extpub_compat_version => "same as extpub_version, but for BIP49",
		extprv_segwit_version => "same as extprv_version, but for BIP84",
		extpub_segwit_version => "same as extpub_version, but for BIP84",

		bip44_coin => "bip44 coin number, eg. 0",
	);

You can then C<register> this network:

	Bitcoin::Crypto::Network->register(%config);

Your program will now be able to import keys for that network but all keys
created from other sources will be treated as the default (I<Bitcoin>). You
need to C<set_default> to make all new keys use it. If your usage is not
restrained to a single network, it might be better to set a network manually to
a single key with its C<set_network> method:

	$priv->set_network('network_id');

Remember that if you don't specify network field for some feature you won't be
able to use it. For example, the module will complain if you try to generate
segwit address without C<segwit_hrp> field set.

=head1 METHODS

=head2 register

	$network_object = $class->register(%config)
	$network_object = $object->register()

Adds a network instance to a list of known networks.

Calls L</new> with keys present in C<%config> hash when called in class
context.

Returns the network instance.

=head2 set_default

	$network_object = $object->set_default()

Sets a network as the default one. All newly created private and public keys
will be bound to this network.

Returns the network instance.

=head2 supports_segwit

	$bool = $object->supports_segwit()

Returns a boolean which can be used to determine whether a given network has
SegWit configured.

=head2 new

	$network_object = $class->new(%config)

Creates a new network instance. See L</CONFIGURATION> for a list of possible
C<%config> keys.

=head2 get

	$network_object = $class->get($id = undef)

Without arguments, returns the default network configuration as the
C<Bitcoin::Crypto::Network> instance.

With the C<$id> argument (string), returns the instance of a configuration
matching the id.

Throws an exception if network doesn't exist.

=head2 find

	@network_objects = $class->find($sub = undef)

Without arguments, returns a list of all registered network identifiers.

With the C<$sub> argument (coderef), searches for all networks that pass the
criteria and returns their ids. The C<$sub> will be passed all the instances of
registered networks, one at a time. If must perform required checks and return
a boolean value. All the networks that pass this test will be returned.
Example:

	sub {
		my $instance = shift;
		return $instance->name eq 'Some name';
	}

Returns a list of network instances (objects).

=head1 SEE ALSO

L<Bitcoin::Crypto::Key::ExtPrivate>

L<Bitcoin::Crypto::Key::Private>

