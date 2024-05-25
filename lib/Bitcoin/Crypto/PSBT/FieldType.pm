package Bitcoin::Crypto::PSBT::FieldType;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types qw(Object Str Maybe HashRef PositiveOrZeroInt Enum);

use namespace::clean;

use constant {
	REQUIRED => 'required',
	AVAILABLE => 'available',
};

use constant {
	GLOBAL => 'global',
	INPUT => 'in',
	OUTPUT => 'out',
};

has param 'name' => (
	isa => Str,
);

has param 'code' => (
	isa => PositiveOrZeroInt,
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

my %types = (

	# GLOBAL
	PSBT_GLOBAL_UNSIGNED_TX => {
		code => 0x00,
		key_data => undef,
		value_data => "<bytes transaction>",
		version_status => {
			0 => REQUIRED,
		},
	},
	PSBT_GLOBAL_XPUB => {
		code => 0x01,
		key_data => "<bytes xpub>",
		value_data => "<4 byte fingerprint> <32-bit little endian uint path element>*",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_GLOBAL_TX_VERSION => {
		code => 0x02,
		key_data => undef,
		value_data => "<32-bit little endian int version>",
		version_status => {
			2 => REQUIRED,
		},
	},
	PSBT_GLOBAL_FALLBACK_LOCKTIME => {
		code => 0x03,
		key_data => undef,
		value_data => "<32-bit little endian uint locktime>",
		version_status => {
			2 => AVAILABLE,
		},
	},
	PSBT_GLOBAL_INPUT_COUNT => {
		code => 0x04,
		key_data => undef,
		value_data => "<compact size uint input count>",
		version_status => {
			2 => REQUIRED,
		},
	},
	PSBT_GLOBAL_OUTPUT_COUNT => {
		code => 0x05,
		key_data => undef,
		value_data => "<compact size uint input count>",
		version_status => {
			2 => REQUIRED,
		},
	},
	PSBT_GLOBAL_TX_MODIFIABLE => {
		code => 0x06,
		key_data => undef,
		value_data => "<8-bit uint flags>",
		version_status => {
			2 => AVAILABLE
		},
	},
	PSBT_GLOBAL_VERSION => {
		code => 0xfb,
		key_data => undef,
		value_data => "<32-bit little endian uint version>",
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
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_WITNESS_UTXO => {
		code => 0x01,
		key_data => undef,
		value_data => "<64-bit little endian int amount> <compact size uint scriptPubKeylen> <bytes scriptPubKey>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_PARTIAL_SIG => {
		code => 0x02,
		key_data => "<bytes pubkey>",
		value_data => "<bytes signature>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_SIGHASH_TYPE => {
		code => 0x03,
		key_data => undef,
		value_data => "<32-bit little endian uint sighash type>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_REDEEM_SCRIPT => {
		code => 0x04,
		key_data => undef,
		value_data => "<bytes redeemScript>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_WITNESS_SCRIPT => {
		code => 0x05,
		key_data => undef,
		value_data => "<bytes witnessScript>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_BIP32_DERIVATION => {
		code => 0x06,
		key_data => "<bytes pubkey>",
		value_data => "<4 byte fingerprint> <32-bit little endian uint path element>*",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_FINAL_SCRIPTSIG => {
		code => 0x07,
		key_data => undef,
		value_data => "<bytes scriptSig>",
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
	PSBT_IN_PREVIOUS_TXID => {
		code => 0x0e,
		key_data => undef,
		value_data => "<32 byte txid>",
		version_status => {
			2 => REQUIRED,
		},
	},
	PSBT_IN_OUTPUT_INDEX => {
		code => 0x0f,
		key_data => undef,
		value_data => "<32-bit little endian uint index>",
		version_status => {
			2 => REQUIRED,
		},
	},
	PSBT_IN_SEQUENCE => {
		code => 0x10,
		key_data => undef,
		value_data => "<32-bit little endian uint sequence>",
		version_status => {
			2 => AVAILABLE,
		},
	},
	PSBT_IN_REQUIRED_TIME_LOCKTIME => {
		code => 0x11,
		key_data => undef,
		value_data => "<32-bit little endian uint locktime>",
		version_status => {
			2 => AVAILABLE,
		},
	},
	PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
		code => 0x12,
		key_data => undef,
		value_data => "<32-bit uint locktime>",
		version_status => {
			2 => AVAILABLE,
		},
	},
	PSBT_IN_TAP_KEY_SIG => {
		code => 0x13,
		key_data => undef,
		value_data => "<64 or 65 byte signature>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_TAP_SCRIPT_SIG => {
		code => 0x14,
		key_data => "<32 byte xonlypubkey> <leafhash>",
		value_data => "<64 or 65 byte signature>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_TAP_LEAF_SCRIPT => {
		code => 0x15,
		key_data => "<bytes control block>",
		value_data => "<bytes script> <8-bit uint leaf version>",
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
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_TAP_INTERNAL_KEY => {
		code => 0x17,
		key_data => undef,
		value_data => "<32 byte xonlypubkey>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_IN_TAP_MERKLE_ROOT => {
		code => 0x18,
		key_data => undef,
		value_data => "<32-byte hash>",
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
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_OUT_WITNESS_SCRIPT => {
		code => 0x01,
		key_data => undef,
		value_data => "<bytes witnessScript>",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_OUT_BIP32_DERIVATION => {
		code => 0x02,
		key_data => "<bytes public key>",
		value_data => "<4 byte fingerprint> <32-bit little endian uint path element>*",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
	PSBT_OUT_AMOUNT => {
		code => 0x03,
		key_data => undef,
		value_data => "<64-bit int amount>",
		version_status => {
			2 => REQUIRED,
		},
	},
	PSBT_OUT_SCRIPT => {
		code => 0x04,
		key_data => undef,
		value_data => "<bytes script>",
		version_status => {
			2 => REQUIRED,
		},
	},
	PSBT_OUT_TAP_INTERNAL_KEY => {
		code => 0x05,
		key_data => undef,
		value_data => "<32 byte xonlypubkey>",
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
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},
);

%types = map { $_, __PACKAGE__->new(name => $_, %{$types{$_}}) } keys %types;
my %types_reverse;
foreach my $type (values %types) {
	$types_reverse{$type->get_map_type}{$type->code} = $type->name;
}

signature_for get_field_by_code => (
	method => Str,
	positional => [Enum [GLOBAL, INPUT, OUTPUT], PositiveOrZeroInt],
);

sub get_field_by_code
{
	my ($self, $map_type, $code) = @_;

	Bitcoin::Crypto::Exception::PSBT->raise(
		"unknown field type code $code in map $map_type"
	) unless exists $types_reverse{$map_type}{$code};

	return $types{$types_reverse{$map_type}{$code}};
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

signature_for get_map_type => (
	method => Object,
	positional => [],
);

sub get_map_type
{
	my ($self) = @_;
	my $name = $self->name;

	# module programming error has occured if those die
	die unless $name =~ /^PSBT_([A-Z]+)_/;
	my $namespace = lc $1;
	die unless grep { $namespace eq $_ } GLOBAL, INPUT, OUTPUT;

	return $namespace;
}

1;

