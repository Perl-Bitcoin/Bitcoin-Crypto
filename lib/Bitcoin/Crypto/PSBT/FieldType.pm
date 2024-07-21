package Bitcoin::Crypto::PSBT::FieldType;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use List::Util qw(any notall);

use Bitcoin::Crypto qw(btc_extpub btc_pub btc_transaction btc_script);
use Bitcoin::Crypto::Transaction::Output;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Util qw(pack_compactsize unpack_compactsize);
use Bitcoin::Crypto::Helpers qw(ensure_length);    # loads Math::BigInt
use Bitcoin::Crypto::Types qw(Object Str Maybe HashRef PositiveOrZeroInt Enum CodeRef PSBTMapType);

use namespace::clean;

use constant {
	REQUIRED => 'required',
	AVAILABLE => 'available',
};

has param 'name' => (
	isa => Str,
);

has param 'code' => (
	isa => PositiveOrZeroInt,
);

has param 'map_type' => (
	isa => PSBTMapType,
	lazy => sub {
		my $self = shift;
		my $name = $self->name;
		die unless $name =~ /^PSBT_([A-Z]+)_/;
		return lc $1;
	}
);

has param 'serializer' => (
	isa => CodeRef,
	default => sub {
		sub { $_[0] }
	},
);

has param 'deserializer' => (
	isa => CodeRef,
	default => sub {
		sub { $_[0] }
	},
);

has param 'key_serializer' => (
	isa => CodeRef,
	default => sub {
		sub { $_[0] }
	},
);

has param 'key_deserializer' => (
	isa => CodeRef,
	default => sub {
		sub { $_[0] }
	},
);

has option 'validator' => (
	isa => CodeRef,
);

has param 'key_data' => (
	isa => Maybe [Str],
);

has param 'value_data' => (
	isa => Str,
);

has param 'version_status' => (
	isa => HashRef,
);

# REUSABLE SERIALIZERS

my %uint_32bitLE_serializers = (
	serializer => sub { pack 'V', shift },
	deserializer => sub { unpack 'V', shift },
);

my %uint_compactsize_serializers = (
	serializer => sub { pack_compactsize shift },
	deserializer => sub { unpack_compactsize shift },
);

my %fingerprint_and_path_serializers = (
	serializer => sub {
		my @vals = @{shift()};
		my $fingerprint = shift @vals;
		return $fingerprint . pack 'V*', @vals;
	},
	deserializer => sub {
		my $val = shift;
		my $fingerprint = substr $val, 0, 4, '';
		return [
			$fingerprint,
			unpack 'V*', $val,
		];
	},
);

my %script_serializers = (
	serializer => sub { shift->to_serialized },
	deserializer => sub { btc_script->from_serialized(shift) },
);

my %proprietary_key_serializers = (
	key_serializer => sub {
		my ($ident, $subkey, @rest) = @{shift()};

		die 'invalid data for PROPRIETARY, expected identifier data and subkey data'
			if @rest > 0;

		my $result = '';
		$result .= pack_compactsize(length $ident);
		$result .= $ident;
		$result .= pack_compactsize(length $subkey);
		$result .= $subkey;

		return $result;
	},
	key_deserializer => sub {
		my $val = shift;
		my $pos = 0;

		my $ident_len = unpack_compactsize($val, \$pos);
		my $ident = substr $val, $pos, $ident_len;
		$pos += $ident_len;

		my $subkey_len = unpack_compactsize($val, \$pos);
		my $subkey = substr $val, $pos, $subkey_len;
		$pos += $subkey_len;

		return [$ident, $subkey];
	},
);

# TYPES

my %types = (

	# GLOBAL

	PSBT_GLOBAL_UNSIGNED_TX => {
		code => 0x00,
		key_data => undef,
		value_data => "<bytes transaction>",
		serializer => sub { shift->to_serialized },
		deserializer => sub { btc_transaction->from_serialized(shift) },
		validator => sub {
			my ($tx) = @_;

			die 'must not have signatures'
				if notall { $_->signature_script->is_empty } @{$tx->inputs};

			die 'must be in non-witness format'
				if any { $_->has_witness } @{$tx->inputs};
		},
		version_status => {
			0 => REQUIRED,
		},
	},

	PSBT_GLOBAL_XPUB => {
		code => 0x01,
		key_data => "<bytes xpub>",
		value_data => "<4 byte fingerprint> <32-bit little endian uint path element>*",
		key_serializer => sub { shift->to_serialized },
		key_deserializer => sub { btc_extpub->from_serialized(shift) },
		%fingerprint_and_path_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_GLOBAL_TX_VERSION => {
		code => 0x02,
		key_data => undef,
		value_data => "<32-bit little endian int version>",
		%uint_32bitLE_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_GLOBAL_FALLBACK_LOCKTIME => {
		code => 0x03,
		key_data => undef,
		value_data => "<32-bit little endian uint locktime>",
		%uint_32bitLE_serializers,
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_GLOBAL_INPUT_COUNT => {
		code => 0x04,
		key_data => undef,
		value_data => "<compact size uint input count>",
		%uint_compactsize_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_GLOBAL_OUTPUT_COUNT => {
		code => 0x05,
		key_data => undef,
		value_data => "<compact size uint input count>",
		%uint_compactsize_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_GLOBAL_TX_MODIFIABLE => {
		code => 0x06,
		key_data => undef,
		value_data => "<8-bit uint flags>",
		serializer => sub {
			my $hash = shift;
			my $raw = $hash->{raw_value} // 0;
			$raw |= 0x01 if $hash->{inputs_modifiable};
			$raw |= 0x02 if $hash->{outputs_modifiable};
			$raw |= 0x04 if $hash->{has_sighash_single};

			return pack 'C', $raw;
		},
		deserializer => sub {
			my $raw = unpack 'C', shift;

			return {
				raw_value => $raw,
				inputs_modifiable => !!($raw & 0x01),
				outputs_modifiable => !!($raw & 0x02),
				has_sighash_single => !!($raw & 0x04),
			};
		},
		version_status => {
			2 => AVAILABLE
		},
	},

	PSBT_GLOBAL_VERSION => {
		code => 0xfb,
		key_data => undef,
		value_data => "<32-bit little endian uint version>",
		%uint_32bitLE_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_GLOBAL_PROPRIETARY => {
		code => 0xfc,
		key_data =>
			"<compact size uint identifier length> <bytes identifier> <compact size uint subtype> <bytes subkey_data>",
		value_data => "<bytes data>",
		%proprietary_key_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	# INPUT

	PSBT_IN_NON_WITNESS_UTXO => {
		code => 0x00,
		key_data => undef,
		value_data => "<bytes transaction>",
		serializer => sub { shift->to_serialized },
		deserializer => sub { btc_transaction->from_serialized(shift) },
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_WITNESS_UTXO => {
		code => 0x01,
		key_data => undef,
		value_data => "<64-bit little endian int amount> <compact size uint scriptPubKeylen> <bytes scriptPubKey>",
		serializer => sub { shift->to_serialized },
		deserializer => sub { Bitcoin::Crypto::Transaction::Output->from_serialized(shift) },
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_PARTIAL_SIG => {
		code => 0x02,
		key_data => "<bytes pubkey>",
		value_data => "<bytes signature>",
		key_serializer => sub { shift->to_serialized },
		key_deserializer => sub { btc_pub->from_serialized(shift) },
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_SIGHASH_TYPE => {
		code => 0x03,
		key_data => undef,
		value_data => "<32-bit little endian uint sighash type>",
		%uint_32bitLE_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_REDEEM_SCRIPT => {
		code => 0x04,
		key_data => undef,
		value_data => "<bytes redeemScript>",
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_WITNESS_SCRIPT => {
		code => 0x05,
		key_data => undef,
		value_data => "<bytes witnessScript>",
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_BIP32_DERIVATION => {
		code => 0x06,
		key_data => "<bytes pubkey>",
		value_data => "<4 byte fingerprint> <32-bit little endian uint path element>*",
		key_serializer => sub { shift->to_serialized },
		key_deserializer => sub { btc_pub->from_serialized(shift) },
		%fingerprint_and_path_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_FINAL_SCRIPTSIG => {
		code => 0x07,
		key_data => undef,
		value_data => "<bytes scriptSig>",
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_FINAL_SCRIPTWITNESS => {
		code => 0x08,
		key_data => undef,
		value_data => "<bytes scriptWitness>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_POR_COMMITMENT => {
		code => 0x09,
		key_data => undef,
		value_data => "<bytes porCommitment>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_RIPEMD160 => {
		code => 0x0a,
		key_data => "<20-byte hash>",
		value_data => "<bytes preimage>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_SHA256 => {
		code => 0x0b,
		key_data => "<32-byte hash>",
		value_data => "<bytes preimage>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_HASH160 => {
		code => 0x0c,
		key_data => "<20-byte hash>",
		value_data => "<bytes preimage>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_HASH256 => {
		code => 0x0d,
		key_data => "<32-byte hash>",
		value_data => "<bytes preimage>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	# NOTE: as usual, txids are represented in different byte order when serialized
	PSBT_IN_PREVIOUS_TXID => {
		code => 0x0e,
		key_data => undef,
		value_data => "<32 byte txid>",
		serializer => sub { scalar reverse shift },
		deserializer => sub { scalar reverse shift },
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_IN_OUTPUT_INDEX => {
		code => 0x0f,
		key_data => undef,
		value_data => "<32-bit little endian uint index>",
		%uint_32bitLE_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_IN_SEQUENCE => {
		code => 0x10,
		key_data => undef,
		value_data => "<32-bit little endian uint sequence>",
		%uint_32bitLE_serializers,
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_IN_REQUIRED_TIME_LOCKTIME => {
		code => 0x11,
		key_data => undef,
		value_data => "<32-bit little endian uint locktime>",
		%uint_32bitLE_serializers,
		validator => sub {
			my ($value) = @_;
			die 'must be greather than or equal to 500000000'
				if $value < 500000000;
		},
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
		code => 0x12,
		key_data => undef,
		value_data => "<32-bit uint locktime>",
		%uint_32bitLE_serializers,
		validator => sub {
			my ($value) = @_;
			die 'must be less than 500000000'
				unless $value < 500000000;
		},
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_KEY_SIG => {
		code => 0x13,
		key_data => undef,
		value_data => "<64 or 65 byte signature>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_SCRIPT_SIG => {
		code => 0x14,
		key_data => "<32 byte xonlypubkey> <leafhash>",
		value_data => "<64 or 65 byte signature>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_LEAF_SCRIPT => {
		code => 0x15,
		key_data => "<bytes control block>",
		value_data => "<bytes script> <8-bit uint leaf version>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_BIP32_DERIVATION => {
		code => 0x16,
		key_data => "<32 byte xonlypubkey>",
		value_data =>
			"<compact size uint number of hashes> <32 byte leaf hash>* <4 byte fingerprint> <32-bit little endian uint path element>*",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_INTERNAL_KEY => {
		code => 0x17,
		key_data => undef,
		value_data => "<32 byte xonlypubkey>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_MERKLE_ROOT => {
		code => 0x18,
		key_data => undef,
		value_data => "<32-byte hash>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_PROPRIETARY => {
		code => 0xfc,
		key_data =>
			"<compact size uint identifier length> <bytes identifier> <compact size uint subtype> <bytes subkey_data>",
		value_data => "<bytes data>",
		%proprietary_key_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	# OUTPUT
	PSBT_OUT_REDEEM_SCRIPT => {
		code => 0x00,
		key_data => undef,
		value_data => "<bytes redeemScript>",
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_WITNESS_SCRIPT => {
		code => 0x01,
		key_data => undef,
		value_data => "<bytes witnessScript>",
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_BIP32_DERIVATION => {
		code => 0x02,
		key_data => "<bytes public key>",
		value_data => "<4 byte fingerprint> <32-bit little endian uint path element>*",
		key_serializer => sub { shift->to_serialized },
		key_deserializer => sub { btc_pub->from_serialized(shift) },
		%fingerprint_and_path_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_AMOUNT => {
		code => 0x03,
		key_data => undef,
		value_data => "<64-bit int amount>",
		serializer => sub { scalar reverse ensure_length shift->to_bytes, 8 },
		deserializer => sub { Math::BigInt->from_bytes(scalar reverse shift) },
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_OUT_SCRIPT => {
		code => 0x04,
		key_data => undef,
		value_data => "<bytes script>",
		%script_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_OUT_TAP_INTERNAL_KEY => {
		code => 0x05,
		key_data => undef,
		value_data => "<32 byte xonlypubkey>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_TAP_TREE => {
		code => 0x06,
		key_data => undef,
		value_data =>
			"{<8-bit uint depth> <8-bit uint leaf version> <compact size uint scriptlen> <bytes script>}*",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_TAP_BIP32_DERIVATION => {
		code => 0x07,
		key_data => "<32 byte xonlypubkey>",
		value_data =>
			"<compact size uint number of hashes> <32 byte leaf hash>* <4 byte fingerprint> <32-bit little endian uint path element>*",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_PROPRIETARY => {
		code => 0xfc,
		key_data =>
			"<compact size uint identifier length> <bytes identifier> <compact size uint subtype> <bytes subkey_data>",
		value_data => "<bytes data>",
		%proprietary_key_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
);

%types = map { $_, __PACKAGE__->new(name => $_, %{$types{$_}}) } keys %types;
my %types_reverse;
foreach my $type (values %types) {
	$types_reverse{$type->map_type}{$type->code} = $type->name;
}

signature_for get_field_by_code => (
	method => Str,
	positional => [PSBTMapType, PositiveOrZeroInt],
);

sub get_field_by_code
{
	my ($self, $map_type, $code) = @_;

	return $types{$types_reverse{$map_type}{$code}}
		if exists $types_reverse{$map_type}{$code};

	return $self->new(
		name => 'UNKNOWN',
		map_type => $map_type,
		code => $code,
		key_data => 'unknown',
		value_data => 'unknown',
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	);
}

signature_for get_field_by_name => (
	method => Str,
	positional => [Str],
);

sub get_field_by_name
{
	my ($self, $name) = @_;

	Bitcoin::Crypto::Exception::PSBT->raise(
		"unknown field type $name"
	) unless exists $types{$name};

	return $types{$name};
}

signature_for get_fields_required_in_version => (
	method => Str,
	positional => [PositiveOrZeroInt],
);

sub get_fields_required_in_version
{
	my ($class, $version) = @_;

	return [
		grep {
			$_->required_in_version($version)
		} values %types
	];
}

signature_for has_key_data => (
	method => Object,
	positional => [],
);

sub has_key_data
{
	my ($self) = @_;

	return defined $self->key_data;
}

signature_for available_in_version => (
	method => Object,
	positional => [PositiveOrZeroInt],
);

sub available_in_version
{
	my ($self, $version) = @_;

	return defined $self->version_status->{$version};
}

signature_for required_in_version => (
	method => Object,
	positional => [PositiveOrZeroInt],
);

sub required_in_version
{
	my ($self, $version) = @_;

	return ($self->version_status->{$version} // '') eq REQUIRED;
}

1;

