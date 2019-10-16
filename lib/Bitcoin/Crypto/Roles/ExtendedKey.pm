package Bitcoin::Crypto::Roles::ExtendedKey;

use Modern::Perl "2010";
use Moo::Role;
use List::Util qw(first);
use Carp qw(croak);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Types qw(IntMaxBits StrExactLength);
use Bitcoin::Crypto::PrivateKey;
use Bitcoin::Crypto::PublicKey;
use Bitcoin::Crypto::Util qw(get_path_info);
use Bitcoin::Crypto::Helpers qw(pad_hex ensure_length hash160);
use Bitcoin::Crypto::Network qw(find_network get_network);
use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);

with "Bitcoin::Crypto::Roles::Key";

has "depth" => (
	is => "ro",
	isa => IntMaxBits[8],
	default => 0
);

has "parentFingerprint" => (
	is => "ro",
	isa => StrExactLength[4],
	default => sub { pack "x4" }
);

has "childNumber" => (
	is => "ro",
	isa => IntMaxBits[32],
	default => 0
);

has "chainCode" => (
	is => "ro",
	isa => StrExactLength[32]
);

sub _buildArgs
{
	my ($class, @params) = @_;

	croak {reason => "key_create", message => "invalid arguments passed to key constructor"}
		if @params < 2 || @params > 5;

	my %ret = (
		keyInstance => $class->_createKey($params[0]),
		chainCode => $params[1],
	);

	$ret{childNumber} = $params[2]
		if @params >= 3;
	$ret{parentFingerprint} = $params[3]
		if @params >= 4;
	$ret{depth} = $params[4]
		if @params >= 5;

	return %ret;
}

sub toSerialized
{
	my ($self) = @_;

	my $network_key = "ext" . ($self->_isPrivate ? "prv" : "pub") . "_version";
	my $version = $self->network->{$network_key};
	# network field is not required, lazy check for completeness
	croak {reason => "network_config", message => "no $network_key found in network configuration"}
		unless defined $version;

	# version number (4B)
	my $serialized = ensure_length pack("N", $version), 4;
	# depth (1B)
	$serialized .= ensure_length pack("C", $self->depth), 1;
	# parent's fingerprint (4B) - ensured
	$serialized .= $self->parentFingerprint;
	# child number (4B)
	$serialized .= ensure_length pack("N", $self->childNumber), 4;
	# chain code (32B) - ensured
	$serialized .= $self->chainCode;
	# key entropy (1 + 32B or 33B)
	$serialized .= ensure_length $self->rawKey, $config{key_max_length} + 1;

	return $serialized;
}

sub fromSerialized
{
	my ($class, $serialized, $network) = @_;
	# expected length is 78
	if (defined $serialized && length $serialized == 78) {
		my $format = "a4aa4a4a32a33";
		my ($version, $depth, $fingerprint, $number, $chain_code, $data) = unpack($format, $serialized);

		my $is_private = pack("x") eq substr $data, 0, 1;
		croak {reason => "key_create", message => "invalid class used, key is " . ($is_private ? "private" : "public")}
			if $is_private != $class->_isPrivate;
		$data = substr $data, 1, $config{key_max_length}
			if $is_private;

		$version = unpack "N", $version;
		my $network_key = "ext" . ($class->_isPrivate ? "prv" : "pub") . "_version";
		my @found_networks = find_network($network_key => $version);
		@found_networks = first { $_ eq $network } @found_networks if defined $network;

		croak {reason => "key_create", message => "found multiple networks possible for given serialized key"}
			if @found_networks > 1;
		croak {reason => "key_create", message => "network name $network cannot be used for given serialized key"}
			if @found_networks == 0 && defined $network;
		croak {reason => "network_config", message => "couldn't find network for serialized key version $version"}
			if @found_networks == 0;

		my $key = $class->new(
			$data,
			$chain_code,
			unpack("N", $number),
			$fingerprint,
			unpack("C", $depth)
		);
		$key->setNetwork(@found_networks);

		return $key;
	} else {
		croak {reason => "key_create", message => "input data does not look like a valid serialized extended key"};
	}
}

sub toSerializedBase58
{
	my ($self) = @_;
	my $serialized = $self->toSerialized();
	return encode_base58check $serialized;
}

sub fromSerializedBase58
{
	my ($class, $base58, $network) = @_;
	return $class->fromSerialized(decode_base58check($base58), $network);
}

sub getBasicKey
{
	my ($self) = @_;
	my $entropy = $self->rawKey;
	my $base_class = "Bitcoin::Crypto::" . ($self->_isPrivate ? "PrivateKey" : "PublicKey");
	my $basic_key =  $base_class->fromBytes($entropy);
	$basic_key->setNetwork($self->network);

	return $basic_key;
}

sub getFingerprint
{
	my ($self, $len) = @_;
	$len //= 4;

	my $pubkey = $self->rawKey("public_compressed");
	my $identifier = hash160($pubkey);
	return substr $identifier, 0, 4;
}

sub deriveKey
{
	my ($self, $path) = @_;
	my $path_info = get_path_info $path;

	croak {reason => "key_derive", message => "invalid key derivation path supplied"}
		unless defined $path_info;
	croak {reason => "key_derive", message => "cannot derive private key from public key"}
		if !$self->_isPrivate && $path_info->{private};

	my $key = $self;
	for my $child_num (@{$path_info->{path}}) {
		my $hardened = $child_num >= $config{max_child_keys};
		# croaks if hardened-from-public requested
		# croaks if key is invalid
		$key = $key->_deriveKeyPartial($child_num, $hardened);
	}

	$key->setNetwork($self->network);
	$key = $key->getPublicKey()
		if $self->_isPrivate && !$path_info->{private};

	return $key;
}

1;
