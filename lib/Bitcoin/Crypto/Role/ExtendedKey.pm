package Bitcoin::Crypto::Role::ExtendedKey;

our $VERSION = "1.001";

use v5.10;
use warnings;
use List::Util qw(first);
use Types::Standard qw(Str);

use Bitcoin::Crypto::Key::Private;
use Bitcoin::Crypto::Key::Public;
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Types qw(IntMaxBits);
use Bitcoin::Crypto::Util qw(get_path_info);
use Bitcoin::Crypto::Helpers qw(pad_hex ensure_length hash160 verify_bytestring);
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);
use Bitcoin::Crypto::Exception;
use Moo::Role;

with "Bitcoin::Crypto::Role::Key";

has "depth" => (
	is => "ro",
	isa => IntMaxBits [8],
	coerce => 1,
	default => 0
);

has "parent_fingerprint" => (
	is => "ro",
	isa => Str->where(q{ length $_ == 4 }),
	default => sub { pack "x4" }
);

has "child_number" => (
	is => "ro",
	isa => IntMaxBits [32],
	coerce => 1,
	default => 0
);

has "chain_code" => (
	is => "ro",
	isa => Str->where(q{ length $_ == 32 }),
	required => 1,
);

sub _build_args
{
	my ($class, @params) = @_;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"invalid arguments passed to key constructor"
	) if @params < 2 || @params > 5;

	my %ret = (
		key_instance => $class->_create_key($params[0]),
		chain_code => $params[1],
	);

	$ret{child_number} = $params[2]
		if @params >= 3;
	$ret{parent_fingerprint} = $params[3]
		if @params >= 4;
	$ret{depth} = $params[4]
		if @params >= 5;

	return %ret;
}

sub to_serialized
{
	my ($self) = @_;

	my $version =
		$self->_is_private ? $self->network->extprv_version : $self->network->extpub_version;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"no extended key version found in network configuration"
	) unless defined $version;

	# version number (4B)
	my $serialized = ensure_length pack("N", $version), 4;

	# depth (1B)
	$serialized .= ensure_length pack("C", $self->depth), 1;

	# parent's fingerprint (4B) - ensured
	$serialized .= $self->parent_fingerprint;

	# child number (4B)
	$serialized .= ensure_length pack("N", $self->child_number), 4;

	# chain code (32B) - ensured
	$serialized .= $self->chain_code;

	# key entropy (1 + 32B or 33B)
	$serialized .= ensure_length $self->raw_key, Bitcoin::Crypto::Config::key_max_length + 1;

	return $serialized;
}

sub from_serialized
{
	my ($class, $serialized, $network) = @_;
	verify_bytestring($serialized);

	# expected length is 78
	if (defined $serialized && length $serialized == 78) {
		my $format = "a4aa4a4a32a33";
		my ($version, $depth, $fingerprint, $number, $chain_code, $data) =
			unpack($format, $serialized);

		my $is_private = pack("x") eq substr $data, 0, 1;

		Bitcoin::Crypto::Exception::KeyCreate->raise(
			"invalid class used, key is " . ($is_private ? "private" : "public")
		) if $is_private != $class->_is_private;

		$data = substr $data, 1, Bitcoin::Crypto::Config::key_max_length
			if $is_private;

		$version = unpack "N", $version;
		my @found_networks = Bitcoin::Crypto::Network->find(
			sub {
				my ($inst) = @_;
				return ($class->_is_private ? $inst->extprv_version : $inst->extpub_version) eq
					$version;
			}
		);
		@found_networks = first { $_ eq $network }
			@found_networks if defined $network;

		Bitcoin::Crypto::Exception::KeyCreate->raise(
			"found multiple networks possible for given serialized key"
		) if @found_networks > 1;

		Bitcoin::Crypto::Exception::KeyCreate->raise(
			"network name $network cannot be used for given serialized key"
		) if @found_networks == 0 && defined $network;

		Bitcoin::Crypto::Exception::NetworkConfig->raise(
			"couldn't find network for serialized key version $version"
		) if @found_networks == 0;

		my $key = $class->new(
			$data,
			$chain_code,
			unpack("N", $number),
			$fingerprint,
			unpack("C", $depth)
		);
		$key->set_network(@found_networks);

		return $key;
	}
	else {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			"input data does not look like a valid serialized extended key"
		);
	}
}

sub to_serialized_base58
{
	my ($self) = @_;
	my $serialized = $self->to_serialized();
	return encode_base58check $serialized;
}

sub from_serialized_base58
{
	my ($class, $base58, $network) = @_;
	return $class->from_serialized(decode_base58check($base58), $network);
}

sub get_basic_key
{
	my ($self) = @_;
	my $base_class = "Bitcoin::Crypto::Key::" . ($self->_is_private ? "Private" : "Public");
	my $basic_key = $base_class->new($self->key_instance);
	$basic_key->set_network($self->network);

	return $basic_key;
}

sub get_fingerprint
{
	my ($self, $len) = @_;
	$len //= 4;

	my $pubkey = $self->raw_key("public_compressed");
	my $identifier = hash160($pubkey);
	return substr $identifier, 0, 4;
}

sub derive_key
{
	my ($self, $path) = @_;
	my $path_info = get_path_info $path;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"invalid key derivation path supplied"
	) unless defined $path_info;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		"cannot derive private key from public key"
	) if !$self->_is_private && $path_info->{private};

	my $key = $self;
	for my $child_num (@{$path_info->{path}}) {
		my $hardened = $child_num >= Bitcoin::Crypto::Config::max_child_keys;

		# dies if hardened-from-public requested
		# dies if key is invalid
		$key = $key->_derive_key_partial($child_num, $hardened);
	}

	$key->set_network($self->network);
	$key = $key->get_public_key()
		if $self->_is_private && !$path_info->{private};

	return $key;
}

1;
