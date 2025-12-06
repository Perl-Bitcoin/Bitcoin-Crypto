package Bitcoin::Crypto::Key::ExtBase;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Scalar::Util qw(blessed);
use Types::Common -sigs;
use Carp qw(carp);
use List::Util qw(none);

use Bitcoin::Crypto::Key::Private;
use Bitcoin::Crypto::Key::Public;
use Bitcoin::Crypto::Constants qw(:bip44 :key);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Util::Internal qw(hash160 to_format);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Exception;

has param 'depth' => (
	isa => IntMaxBits [8],
	default => 0
);

has param 'parent_fingerprint' => (
	coerce => ByteStrLen [4],
	default => (pack 'x4'),
);

has param 'child_number' => (
	isa => IntMaxBits [32],
	default => 0
);

has param 'chain_code' => (
	coerce => ByteStrLen [32],
);

with qw(Bitcoin::Crypto::Role::Key);

sub _is_private
{
	die __PACKAGE__ . '::_is_private is unimplemented';
}

sub _derive_key_partial
{
	die __PACKAGE__ . '::_derive_key_partial is unimplemented';
}

sub _get_network_extkey_version
{
	my ($self, $network, $purpose) = @_;
	$network = $self->network if @_ < 2;
	$purpose = $self->purpose if @_ < 3;

	my $name = 'ext';
	$name .= $self->_is_private ? 'prv' : 'pub';
	$name .= '_compat' if $purpose && $purpose eq BIP44_COMPAT_PURPOSE;
	$name .= '_segwit' if $purpose && $purpose eq BIP44_SEGWIT_PURPOSE;
	$name .= '_version';

	return $network->$name;
}

sub to_serialized
{
	my ($self) = @_;

	my $version = $self->_get_network_extkey_version;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'no extended key version found in network configuration'
	) unless defined $version;

	# version number (4B)
	my $serialized = pack('N', $version);

	# depth (1B)
	$serialized .= pack('C', $self->depth);

	# parent's fingerprint (4B) - ensured
	$serialized .= $self->parent_fingerprint;

	# child number (4B)
	$serialized .= pack('N', $self->child_number);

	# chain code (32B)
	$serialized .= $self->chain_code;

	# key entropy (1 + 32B)
	$serialized .= ensure_length $self->raw_key, KEY_MAX_LENGTH + 1;

	return $serialized;
}

signature_for from_serialized => (
	method => !!1,
	positional => [ByteStr, Maybe [Str], {default => undef}],
);

sub from_serialized
{
	my ($class, $serialized, $network) = @_;

	# expected length is 78
	if (defined $serialized && length $serialized == 78) {
		my ($version, $depth, $fingerprint, $number, $chain_code, $data) =
			unpack 'a4aa4a4a32a33', $serialized;

		my $is_private = pack('x') eq substr $data, 0, 1;

		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'invalid class used, key is ' . ($is_private ? 'private' : 'public')
		) if $is_private != $class->_is_private;

		$data = substr $data, 1, KEY_MAX_LENGTH
			if $is_private;

		$version = unpack 'N', $version;

		my $purpose;
		my @found_networks;

		for my $check_purpose (
			undef,
			BIP44_COMPAT_PURPOSE,
			BIP44_SEGWIT_PURPOSE
			)
		{
			@found_networks = Bitcoin::Crypto::Network->find(
				sub {
					my ($inst) = @_;
					my $this_version = $class->_get_network_extkey_version($inst, $check_purpose);
					return $this_version && $this_version eq $version;
				}
			);

			@found_networks = grep { $_ eq $network } @found_networks
				if defined $network;

			if (@found_networks > 0) {
				$purpose = $check_purpose;
				last;
			}
		}

		if (@found_networks > 1) {
			my $default_network = Bitcoin::Crypto::Network->get->id;

			Bitcoin::Crypto::Exception::KeyCreate->raise(
				'found multiple networks possible for given serialized key: ' . join ', ', @found_networks
			) if none { $_ eq $default_network } @found_networks;

			@found_networks = ($default_network);
		}

		Bitcoin::Crypto::Exception::KeyCreate->raise(
			"network name $network cannot be used for given serialized key"
		) if @found_networks == 0 && defined $network;

		Bitcoin::Crypto::Exception::NetworkConfig->raise(
			"couldn't find network for serialized key version $version"
		) if @found_networks == 0;

		my $key = $class->new(
			_key_instance => $data,
			chain_code => $chain_code,
			child_number => unpack('N', $number),
			parent_fingerprint => $fingerprint,
			depth => unpack('C', $depth),
			network => $found_networks[0],
			(defined $purpose ? (purpose => $purpose) : ()),
		);

		return $key;
	}
	else {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'input data does not look like a valid serialized extended key'
		);
	}
}

sub get_basic_key
{
	my ($self) = @_;
	my $base_class = 'Bitcoin::Crypto::Key::' . ($self->_is_private ? 'Private' : 'Public');
	my $basic_key = $base_class->new(
		_key_instance => $self->_key_instance,
		network => $self->network,
		purpose => $self->purpose,
	);

	return $basic_key;
}

signature_for get_fingerprint => (
	method => !!1,
	positional => [PositiveInt, {default => 4}],
);

sub get_fingerprint
{
	my ($self, $len) = @_;

	my $pubkey = $self->raw_key('public_compressed');
	my $identifier = hash160($pubkey);
	return substr $identifier, 0, 4;
}

sub _get_purpose_from_BIP44
{
	my ($self, $path) = @_;

	# NOTE: only handles BIP44 correctly when it is constructed with Bitcoin::Crypto::BIP44
	# NOTE: when deriving new keys, we do not care about previous state:
	# - if BIP44 is further derived, it is not BIP44 anymore
	# - if BIP44 is derived as a new BIP44, the old one is like the new master key
	# because of that, set purpose to undef if path is not BIP44

	return undef
		unless blessed $path && $path->isa('Bitcoin::Crypto::BIP44');

	return $self->purpose
		if $path->get_from_account || $path->public;

	return $path->purpose;
}

signature_for derive_key => (
	method => !!1,
	positional => [Defined],
);

sub derive_key
{
	my ($self, $path) = @_;

	# $path must be remembered for BIP44 operation below
	my $path_info = DerivationPath->assert_coerce($path);

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		'cannot derive key: key type mismatch'
	) if !!$self->_is_private ne !!$path_info->private;

	my $key = $self;
	for my $child_num (@{$path_info->path}) {
		my $hardened = $child_num >= MAX_CHILD_KEYS;

		# dies if hardened-from-public requested
		# dies if key is invalid
		$key = $key->_derive_key_partial($child_num, $hardened);
	}

	$key->set_network($self->network);
	$key->set_purpose($self->_get_purpose_from_BIP44($path));

	return $key;
}

1;

# Internal use only

