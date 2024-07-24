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
use Bitcoin::Crypto::Types
	qw(Object Str Maybe HashRef ByteStr ArrayRef PositiveOrZeroInt Enum CodeRef PSBTMapType BitcoinScript InstanceOf SatoshiAmount Tuple IntMaxBits);

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
		sub {
			state $sig = signature(positional => [ByteStr]);
			my $value = ($sig->(@_))[0];
			return $value;
		}
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
		sub {
			state $sig = signature(positional => [ByteStr]);
			my $value = ($sig->(@_))[0];
			return $value;
		}
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

has option 'key_data' => (
	isa => Str,
);

has param 'value_data' => (
	isa => Str,
);

has param 'version_status' => (
	isa => HashRef,
);

# REUSABLE SERIALIZERS

my %transaction_serializers = (
	value_data => "Bitcoin::Crypto::Transaction object",
	serializer => sub {
		state $sig = signature(positional => [InstanceOf ['Bitcoin::Crypto::Transaction']]);
		my $value = ($sig->(@_))[0];
		return $value->to_serialized;
	},
	deserializer => sub { btc_transaction->from_serialized(shift) },
);

my %uint_32bitLE_serializers = (
	value_data => "32-bit positive integer value",
	serializer => sub {
		state $sig = signature(positional => [IntMaxBits [32]]);
		my $value = ($sig->(@_))[0];
		return pack 'V', $value;
	},
	deserializer => sub { unpack 'V', shift },
);

my %uint_compactsize_serializers = (
	value_data => "Positive integer value",
	serializer => sub {
		state $sig = signature(positional => [PositiveOrZeroInt]);
		my $value = ($sig->(@_))[0];
		return pack_compactsize $value;
	},
	deserializer => sub { unpack_compactsize shift },
);

my %fingerprint_and_path_serializers = (
	value_data => "Array reference, where the first item is a fingerprint and the rest are integer path elements",
	serializer => sub {
		state $sig = signature(positional => [ByteStr, ArrayRef [PositiveOrZeroInt], {slurpy => !!1}]);
		my ($fingerprint, $path) = $sig->(@{$_[0]});

		return $fingerprint . pack 'V*', @$path;
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
	value_data => "Bitcoin::Crypto::Script object",
	serializer => sub {
		state $sig = signature(positional => [BitcoinScript]);
		my $value = ($sig->(@_))[0];
		return $value->to_serialized;
	},
	deserializer => sub { btc_script->from_serialized(shift) },
);

my %proprietary_key_serializers = (
	key_data => "Array reference with two bytestring items",
	key_serializer => sub {
		state $sig = signature(positional => [Tuple [ByteStr, ByteStr]]);
		my ($ident, $subkey) = @{($sig->(@_))[0]};

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

my %public_key_serializers = (
	key_data => "Bitcoin::Crypto::Key::Public object",
	key_serializer => sub {
		state $sig = signature(positional => [InstanceOf ['Bitcoin::Crypto::Key::Public']]);
		my $value = ($sig->(@_))[0];
		return $value->to_serialized;
	},
	key_deserializer => sub { btc_pub->from_serialized(shift) },
);

# TYPES

my %types = (

	# GLOBAL

	PSBT_GLOBAL_UNSIGNED_TX => {
		code => 0x00,
		%transaction_serializers,
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
		key_data => "Bitcoin::Crypto::Key::ExtPublic object",
		key_serializer => sub {
			state $sig = signature(positional => [InstanceOf ['Bitcoin::Crypto::Key::ExtPublic']]);
			my $value = ($sig->(@_))[0];
			return $value->to_serialized;
		},
		key_deserializer => sub { btc_extpub->from_serialized(shift) },
		%fingerprint_and_path_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_GLOBAL_TX_VERSION => {
		code => 0x02,
		%uint_32bitLE_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_GLOBAL_FALLBACK_LOCKTIME => {
		code => 0x03,
		%uint_32bitLE_serializers,
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_GLOBAL_INPUT_COUNT => {
		code => 0x04,
		%uint_compactsize_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_GLOBAL_OUTPUT_COUNT => {
		code => 0x05,
		%uint_compactsize_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_GLOBAL_TX_MODIFIABLE => {
		code => 0x06,
		value_data => "Hash reference with flags: inputs_modifiable, outputs_modifiable, has_sighash_single",
		serializer => sub {
			state $sig = signature(positional => [HashRef]);
			my $hash = ($sig->(@_))[0];

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
		%uint_32bitLE_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_GLOBAL_PROPRIETARY => {
		code => 0xfc,
		value_data => "Bytestring value",
		%proprietary_key_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	# INPUT

	PSBT_IN_NON_WITNESS_UTXO => {
		code => 0x00,
		%transaction_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_WITNESS_UTXO => {
		code => 0x01,
		value_data => "Bitcoin::Crypto::Transaction::Output object",
		serializer => sub {
			state $sig = signature(positional => [InstanceOf ['Bitcoin::Crypto::Transaction::Output']]);
			my $value = ($sig->(@_))[0];
			return $value->to_serialized;
		},
		deserializer => sub { Bitcoin::Crypto::Transaction::Output->from_serialized(shift) },
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_PARTIAL_SIG => {
		code => 0x02,
		value_data => "Bytestring value",
		%public_key_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_SIGHASH_TYPE => {
		code => 0x03,
		%uint_32bitLE_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_REDEEM_SCRIPT => {
		code => 0x04,
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_WITNESS_SCRIPT => {
		code => 0x05,
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_BIP32_DERIVATION => {
		code => 0x06,
		%public_key_serializers,
		%fingerprint_and_path_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_FINAL_SCRIPTSIG => {
		code => 0x07,
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_FINAL_SCRIPTWITNESS => {
		code => 0x08,
		value_data => "Bytestring value",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_POR_COMMITMENT => {
		code => 0x09,
		value_data => "Bytestring value",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_RIPEMD160 => {
		code => 0x0a,
		key_data => "Bytestring value",
		value_data => "Bytestring value",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_SHA256 => {
		code => 0x0b,
		key_data => "Bytestring value",
		value_data => "Bytestring value",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_HASH160 => {
		code => 0x0c,
		key_data => "Bytestring value",
		value_data => "Bytestring value",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_HASH256 => {
		code => 0x0d,
		key_data => "Bytestring value",
		value_data => "Bytestring value",
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	# NOTE: as usual, txids are represented in different byte order when serialized
	PSBT_IN_PREVIOUS_TXID => {
		code => 0x0e,
		value_data => "Bytestring value",
		serializer => sub {
			state $sig = signature(positional => [ByteStr]);
			my $value = ($sig->(@_))[0];
			return scalar reverse $value;
		},
		deserializer => sub { scalar reverse shift },
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_IN_OUTPUT_INDEX => {
		code => 0x0f,
		%uint_32bitLE_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_IN_SEQUENCE => {
		code => 0x10,
		%uint_32bitLE_serializers,
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_IN_REQUIRED_TIME_LOCKTIME => {
		code => 0x11,
		%uint_32bitLE_serializers,
		validator => sub {
			my ($value) = @_;
			die 'must be greather than or equal to ' . Bitcoin::Crypto::Constants::locktime_height_threshold
				if $value < Bitcoin::Crypto::Constants::locktime_height_threshold;
		},
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
		code => 0x12,
		%uint_32bitLE_serializers,
		validator => sub {
			my ($value) = @_;
			die 'must be less than ' . Bitcoin::Crypto::Constants::locktime_height_threshold
				unless $value < Bitcoin::Crypto::Constants::locktime_height_threshold;
		},
		version_status => {
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_KEY_SIG => {
		code => 0x13,
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
		value_data => "<32 byte xonlypubkey>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_TAP_MERKLE_ROOT => {
		code => 0x18,
		value_data => "<32-byte hash>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_IN_PROPRIETARY => {
		code => 0xfc,
		value_data => "Bytestring value",
		%proprietary_key_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	# OUTPUT
	PSBT_OUT_REDEEM_SCRIPT => {
		code => 0x00,
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_WITNESS_SCRIPT => {
		code => 0x01,
		%script_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_BIP32_DERIVATION => {
		code => 0x02,
		%public_key_serializers,
		%fingerprint_and_path_serializers,
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_AMOUNT => {
		code => 0x03,
		value_data => "Math::BigInt object",
		serializer => sub {
			state $sig = signature(positional => [SatoshiAmount]);
			my $value = ($sig->(@_))[0];
			return scalar reverse ensure_length $value->to_bytes, 8;
		},
		deserializer => sub { Math::BigInt->from_bytes(scalar reverse shift) },
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_OUT_SCRIPT => {
		code => 0x04,
		%script_serializers,
		version_status => {
			2 => REQUIRED,
		},
	},

	PSBT_OUT_TAP_INTERNAL_KEY => {
		code => 0x05,
		value_data => "<32 byte xonlypubkey>",

		# TODO: taproot not yet supported
		version_status => {
			0 => AVAILABLE,
			2 => AVAILABLE,
		},
	},

	PSBT_OUT_TAP_TREE => {
		code => 0x06,
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
		value_data => "Bytestring value",
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
		key_data => 'Bytestring value',
		value_data => 'Bytestring value',
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

	# sort to have a deterministic error message
	return [
		grep {
			$_->required_in_version($version)
		} map {
			$types{$_}
		} sort keys %types
	];
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

__END__
=head1 NAME

Bitcoin::Crypto::PSBT::FieldType - PSBT field types

=head1 SYNOPSIS

	use Bitcoin::Crypto::PSBT::FieldType;

	my $type = Bitcoin::Crypto::PSBT::FieldType->get_field_by_name('PSBT_IN_OUTPUT_INDEX');

=head1 DESCRIPTION

This is both a library of field types and a small struct-like class for types.

An anonymous instance of this class can be created when a non-defined field type is encountered.

=head1 INTERFACE

=head2 Attributes

=head3 name

B<Required in the constructor.> Name of the field type defined in BIP174.

=head3 code

B<Required in the constructor.> Code of the field type defined in BIP174.

=head3 map_type

B<Available in the constructor.> A map type this field belongs to. If not
passed, it will be guessed from L</name>. Map types are defined as constants in
C<Bitcoin::Crypto::Constants>.

=head3 serializer

B<Available in the constructor.> A coderef which will be used to do DWIM
serialization of the value for easier handling. If not passed, a simple coderef
will be installed which will only coerce format descriptions into bytestrings.

=head3 deserializer

B<Available in the constructor.> A coderef which will be used to do DWIM
deserialization of the value, the reverse of L</serializer>.

=head3 key_serializer

B<Available in the constructor.> A coderef which will be used to do DWIM
serialization of the key for easier handling. If not passed, a simple coderef
will be installed which will only coerce format descriptions into bytestrings.

=head3 key_deserializer

B<Available in the constructor.> A coderef which will be used to do DWIM
deserialization of the key, the reverse of L</key_serializer>.

=head3 validator

B<Available in the constructor.> A coderef which will be used to validate the
value. It will be passed deserialized key (if available) and value. It should
throw a string exception if it encounters a problem. This exception will be
then turned to C<Bitcoin::Crypto::Exception::PSBT>. The return value will be
ignored.

I<predicate:> C<has_validator>

=head3 key_data

B<Available in the constructor.> Key data of the field type. It should be a
string describing what is the effect of deserialization and what the serializer
expects. It may be undefined if the field does not support extra key data.

I<predicate:> C<has_key_data>

=head3 value_data

B<Required in the constructor.> Value data of the field type. It should be a
string describing what is the effect of deserialization and what the serializer
expects.

=head3 version_status

B<Required in the constructor.> A hash reference, where keys are PSBT versions
and values are string, either C<required> or C<available>.

=head2 Methods

=head3 new

	$field = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 get_field_by_code

	$type = $class->get_field_by_code($map_type, $code)

Returns a field type with a given C<$code> for C<$map_type>.

If no such field is defined, a new unknown field type will be created.

=head3 get_field_by_name

	$type = $class->get_field_by_name($name)

Returns a field type with a given C<$name>.

If no such field is defined, an exception will be thrown.

=head3 get_fields_required_in_version

	$fields_aref = $class->get_fields_required_in_version($version)

Returns an array reference of field types which are required in a given C<$version> number.

=head3 required_in_version

	$boolean = $object->required_in_version($version)

Returns true if this field type is required in a given C<$version> number.

=head3 available_in_version

	$boolean = $object->available_in_version($version)

Returns true if this field type is available in a given C<$version> number.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * PSBT - general error with the PSBT

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::PSBT>

=back

=cut

