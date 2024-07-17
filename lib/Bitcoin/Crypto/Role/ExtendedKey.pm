package Bitcoin::Crypto::Role::ExtendedKey;

use v5.10;
use strict;
use warnings;
use Scalar::Util qw(blessed);
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use Carp qw(carp);
use List::Util qw(none);

use Bitcoin::Crypto::Key::Private;
use Bitcoin::Crypto::Key::Public;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types qw(IntMaxBits StrLength Str Object Maybe ByteStr PositiveInt InstanceOf);
use Bitcoin::Crypto::Util qw(get_path_info hash160 to_format);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Exception;
use Moo::Role;

has param 'depth' => (
	isa => IntMaxBits [8],
	default => 0
);

has param 'parent_fingerprint' => (
	isa => StrLength [4, 4],
	default => (pack 'x4'),
);

has param 'child_number' => (
	isa => IntMaxBits [32],
	default => 0
);

has param 'chain_code' => (
	isa => StrLength [32, 32],
);

with qw(Bitcoin::Crypto::Role::Key);

requires '_derive_key_partial';

sub _get_network_extkey_version
{
	my ($self, $network, $purpose) = @_;
	$network //= $self->network;
	$purpose //= $self->purpose;

	my $name = 'ext';
	$name .= $self->_is_private ? 'prv' : 'pub';
	$name .= '_compat' if $purpose && $purpose eq Bitcoin::Crypto::Constants::bip44_compat_purpose;
	$name .= '_segwit' if $purpose && $purpose eq Bitcoin::Crypto::Constants::bip44_segwit_purpose;
	$name .= '_version';

	return $network->$name;
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	my $version = $self->_get_network_extkey_version;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		'no extended key version found in network configuration'
	) unless defined $version;

	# version number (4B)
	my $serialized = ensure_length pack('N', $version), 4;

	# depth (1B)
	$serialized .= ensure_length pack('C', $self->depth), 1;

	# parent's fingerprint (4B) - ensured
	$serialized .= $self->parent_fingerprint;

	# child number (4B)
	$serialized .= ensure_length pack('N', $self->child_number), 4;

	# chain code (32B) - ensured
	$serialized .= $self->chain_code;

	# key entropy (1 + 32B or 33B)
	$serialized .= ensure_length $self->raw_key, Bitcoin::Crypto::Constants::key_max_length + 1;

	return $serialized;
}

signature_for from_serialized => (
	method => Str,
	positional => [ByteStr, Maybe [Str], {default => undef}],
);

sub from_serialized
{
	my ($class, $serialized, $network) = @_;

	# expected length is 78
	if (defined $serialized && length $serialized == 78) {
		my $format = 'a4aa4a4a32a33';
		my ($version, $depth, $fingerprint, $number, $chain_code, $data) =
			unpack($format, $serialized);

		my $is_private = pack('x') eq substr $data, 0, 1;

		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'invalid class used, key is ' . ($is_private ? 'private' : 'public')
		) if $is_private != $class->_is_private;

		$data = substr $data, 1, Bitcoin::Crypto::Constants::key_max_length
			if $is_private;

		$version = unpack 'N', $version;

		my $purpose;
		my @found_networks;

		for my $check_purpose (
			Bitcoin::Crypto::Constants::bip44_purpose,
			Bitcoin::Crypto::Constants::bip44_compat_purpose,
			Bitcoin::Crypto::Constants::bip44_segwit_purpose
			)
		{
			$purpose = $check_purpose;

			@found_networks = Bitcoin::Crypto::Network->find(
				sub {
					my ($inst) = @_;
					my $this_version = $class->_get_network_extkey_version($inst, $purpose);
					return $this_version && $this_version eq $version;
				}
			);
			@found_networks = grep { $_ eq $network } @found_networks
				if defined $network;

			last if @found_networks > 0;
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
			key_instance => $data,
			chain_code => $chain_code,
			child_number => unpack('N', $number),
			parent_fingerprint => $fingerprint,
			depth => unpack('C', $depth),
			network => $found_networks[0],
			purpose => $purpose,
		);

		return $key;
	}
	else {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'input data does not look like a valid serialized extended key'
		);
	}
}

signature_for get_basic_key => (
	method => Object,
	positional => [],
);

sub get_basic_key
{
	my ($self) = @_;
	my $base_class = 'Bitcoin::Crypto::Key::' . ($self->_is_private ? 'Private' : 'Public');
	my $basic_key = $base_class->new(
		key_instance => $self->key_instance,
		network => $self->network,
		purpose => $self->purpose,
	);

	return $basic_key;
}

signature_for get_fingerprint => (
	method => Object,
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
	method => Object,
	positional => [Str | Object],
);

sub derive_key
{
	my ($self, $path) = @_;
	my $path_info = get_path_info $path;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		'invalid key derivation path supplied'
	) unless defined $path_info;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		'cannot derive key: key type mismatch'
	) if !!$self->_is_private ne !!$path_info->private;

	my $key = $self;
	for my $child_num (@{$path_info->path}) {
		my $hardened = $child_num >= Bitcoin::Crypto::Constants::max_child_keys;

		# dies if hardened-from-public requested
		# dies if key is invalid
		$key = $key->_derive_key_partial($child_num, $hardened);
	}

	$key->set_network($self->network);
	$key->set_purpose($self->_get_purpose_from_BIP44($path));

	return $key;
}

### DEPRECATED

sub to_serialized_base58
{
	my ($self) = @_;

	my $class = ref $self;
	carp "$class->to_serialized_base58 is now deprecated. Use to_format [base58 => $class->to_serialized] instead";

	return to_format [base58 => $self->to_serialized];
}

sub from_serialized_base58
{
	my ($class, $base58, $network) = @_;

	carp
		"$class->from_serialized_base58(\$base58) is now deprecated. Use $class->from_serialized([base58 => \$base58]) instead";

	return $class->from_serialized([base58 => $base58], $network);
}

1;

