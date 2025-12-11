package Bitcoin::Crypto::Constants;

use v5.14;
use warnings;

use Config;
use Exporter qw(import);

our @EXPORT_OK;

# These constants are environment-specific and internal only
use constant {
	ivsize => $Config{ivsize},
	is_32bit => $Config{ivsize} == 4,
	is_64bit => $Config{ivsize} >= 8,
};

# just for backcompat, since docs used to include this
use constant p2sh_timestamp_threshold => 1333238400;

BEGIN {
	my %constants = (
		curve_name => 'secp256k1',
		curve_order => pack('H*', 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
		curve_generator => pack(
			'H*',
			'0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
		),

		key_max_length => 32,
		max_child_keys => (1 << 31),
		wif_compressed_byte => "\x01",

		segwit_witness_version => 0,
		taproot_witness_version => 1,
		max_witness_version => 16,

		bip44_purpose => 44,
		bip44_compat_purpose => 49,
		bip44_segwit_purpose => 84,
		bip44_taproot_purpose => 86,

		psbt_magic => pack('H*', '70736274ff'),
		psbt_separator => "\x00",
		psbt_global_map => 'global',
		psbt_input_map => 'in',
		psbt_output_map => 'out',

		sighash_default => 0x00,
		sighash_all => 0x01,
		sighash_none => 0x02,
		sighash_single => 0x03,
		sighash_anyonecanpay => 0x80,

		script_max_stack_elements => 1000,
		script_max_element_size => 520,
		script_max_opcodes => 201,
		script_max_size => 10_000,
		script_max_multisig_pubkeys => 20,
		tapscript_leaf_version => 0xc0,

		locktime_height_threshold => 500_000_000,
		max_sequence_no => 0xffffffff,
		rbf_sequence_no_threshold => 0xffffffff - 2,
		null_utxo => sub () { [pack('x32'), 0xffffffff] },

		units_per_coin => 100_000_000,
		max_money => '2100000000000000',

		bech32 => 'bech32',
		bech32m => 'bech32m',

		use_bigints => $ENV{BITCOIN_CRYPTO_USE_BIGINTS} || !is_64bit,
	);

	my $package = __PACKAGE__;
	my $symtab = do {
		no strict 'refs';
		\%{"${package}::"};
	};

	# simplified procedure borrowed from constant.pm
	foreach my $name (keys %constants) {
		my $value = $constants{$name};

		for my $sym_name ($name, uc $name) {
			if (ref $value eq 'CODE') {
				no strict 'refs';
				*{"${package}::${sym_name}"} = $value;
			}
			elsif (ref $value) {
				die 'bad non-subref reference constant';
			}
			else {
				Internals::SvREADONLY($value, 1);
				$symtab->{$sym_name} = \$value;
			}
		}

		push @EXPORT_OK, uc $name;
	}
}

our %EXPORT_TAGS = (
	all => [@EXPORT_OK],

	curve => [
		qw(
			CURVE_NAME
			CURVE_ORDER
			CURVE_GENERATOR
		)
	],

	key => [
		qw(
			KEY_MAX_LENGTH
			MAX_CHILD_KEYS
			WIF_COMPRESSED_BYTE
		)
	],

	witness => [
		qw(
			SEGWIT_WITNESS_VERSION
			TAPROOT_WITNESS_VERSION
			MAX_WITNESS_VERSION
		)
	],

	bip44 => [
		qw(
			BIP44_PURPOSE
			BIP44_COMPAT_PURPOSE
			BIP44_SEGWIT_PURPOSE
			BIP44_TAPROOT_PURPOSE
		)
	],

	psbt => [
		qw(
			PSBT_MAGIC
			PSBT_SEPARATOR
			PSBT_GLOBAL_MAP
			PSBT_INPUT_MAP
			PSBT_OUTPUT_MAP
		)
	],

	sighash => [
		qw(
			SIGHASH_DEFAULT
			SIGHASH_ALL
			SIGHASH_NONE
			SIGHASH_SINGLE
			SIGHASH_ANYONECANPAY
		)
	],

	script => [
		qw(
			SCRIPT_MAX_STACK_ELEMENTS
			SCRIPT_MAX_ELEMENT_SIZE
			SCRIPT_MAX_OPCODES
			SCRIPT_MAX_SIZE
			SCRIPT_MAX_MULTISIG_PUBKEYS
			TAPSCRIPT_LEAF_VERSION
		)
	],

	transaction => [
		qw(
			RBF_SEQUENCE_NO_THRESHOLD
			NULL_UTXO
			LOCKTIME_HEIGHT_THRESHOLD
			MAX_SEQUENCE_NO
		)
	],

	coin => [
		qw(
			UNITS_PER_COIN
			MAX_MONEY
		)
	],

	bech32 => [
		qw(
			BECH32
			BECH32M
		)
	],
);

1;

__END__
=head1 NAME

Bitcoin::Crypto::Constants - Bitcoin-related constant values

=head1 SYNOPSIS

	use Bitcoin::Crypto::Constants (
		# these constants are grouped under :curve tag
		'CURVE_NAME',
		'CURVE_ORDER',
		'CURVE_GENERATOR',

		# these constants are grouped under :key tag
		'MAX_CHILD_KEYS',
		'KEY_MAX_LENGTH',
		'WIF_COMPRESSED_BYTE',

		# these constants are grouped under :witness tag
		'SEGWIT_WITNESS_VERSION',
		'TAPROOT_WITNESS_VERSION',
		'MAX_WITNESS_VERSION',

		# these constants are grouped under :bip44 tag
		'BIP44_PURPOSE',
		'BIP44_COMPAT_PURPOSE',
		'BIP44_SEGWIT_PURPOSE',
		'BIP44_TAPROOT_PURPOSE',

		# these constants are grouped under :coin tag
		'UNITS_PER_COIN',
		'MAX_MONEY',

		# these constants are grouped under :transaction tag
		'LOCKTIME_HEIGHT_THRESHOLD',
		'MAX_SEQUENCE_NO',
		'RBF_SEQUENCE_NO_THRESHOLD',
		'NULL_UTXO',

		# these constants are grouped under :sighash tag
		'SIGHASH_DEFAULT',
		'SIGHASH_ALL',
		'SIGHASH_NONE',
		'SIGHASH_SINGLE',
		'SIGHASH_ANYONECANPAY',

		# these constants are grouped under :script tag
		'SCRIPT_MAX_STACK_ELEMENTS',
		'SCRIPT_MAX_ELEMENT_SIZE',
		'SCRIPT_MAX_OPCODES',
		'SCRIPT_MAX_SIZE',
		'SCRIPT_MAX_MULTISIG_PUBKEYS',
		'TAPSCRIPT_LEAF_VERSION',

		# these constants are grouped under :psbt tag
		'PSBT_MAGIC',
		'PSBT_SEPARATOR',
		'PSBT_GLOBAL_MAP',
		'PSBT_INPUT_MAP',
		'PSBT_OUTPUT_MAP',

		# these constants are grouped under :bech32 tag
		'BECH32',
		'BECH32M',

		# these constants are ungrouped
		'USE_BIGINTS',
	);

	# or, if you are not sure...
	use Bitcoin::Crypto::Constants qw(:all);

=head1 DESCRIPTION

This package contains named constants for all kinds of values used across
Bitcoin. It is not uncommon to have a need to use these values in code which
interacts with Bitcoin::Crypto.

Each constant can be accessed either by importing it (as shown above) or by
calling a fully qualified name, like C<Bitcoin::Crypto::Constants::MAX_MONEY>.
For backward compatibility, the second form can also be used with lowercase
name: C<Bitcoin::Crypto::Constants::max_money>.

To avoid overly long import statements, constants are organized under tags.
Unless there is a reason not to, it is recommended to import tags instead of
each constant separately. The exception is the C<:all> tag, which should be
used sparingly.

=head1 TAGS

=head2 :all

Imports everything. Should generally be avoided to not clutter the namespace.

=head2 :curve

Contains basic secp256k1 curve data:

L</CURVE_NAME>, L</CURVE_ORDER>, L</CURVE_GENERATOR>

=head2 :key

Contains values which may be required when dealing with keys:

L</MAX_CHILD_KEYS>, L</KEY_MAX_LENGTH>, L</WIF_COMPRESSED_BYTE>

=head2 :witness

Contains values for witness versions:

L</SEGWIT_WITNESS_VERSION>, L</TAPROOT_WITNESS_VERSION>, L</MAX_WITNESS_VERSION>

=head2 :bip44

Contains various BIP44 purpose values:

L</BIP44_PURPOSE>, L</BIP44_COMPAT_PURPOSE>, L</BIP44_SEGWIT_PURPOSE>, L</BIP44_TAPROOT_PURPOSE>

=head2 :coin

Contains very basic coin constants:

L</UNITS_PER_COIN>, L</MAX_MONEY>

=head2 :transaction

Contains constants used together with transactions:

L</LOCKTIME_HEIGHT_THRESHOLD>, L</MAX_SEQUENCE_NO>, L</RBF_SEQUENCE_NO_THRESHOLD>, L</NULL_UTXO>

=head2 :sighash

Contains known sighash values:

L</SIGHASH_DEFAULT>, L</SIGHASH_ALL>, L</SIGHASH_NONE>, L</SIGHASH_SINGLE>, L</SIGHASH_ANYONECANPAY>

=head2 :script

Contains values used during script creation and execution:

L</SCRIPT_MAX_STACK_ELEMENTS>, L</SCRIPT_MAX_ELEMENT_SIZE>, L</SCRIPT_MAX_OPCODES>, L</SCRIPT_MAX_SIZE>, L</SCRIPT_MAX_MULTISIG_PUBKEYS>, L</TAPSCRIPT_LEAF_VERSION>

=head2 :psbt

Contains values useful for PSBTs:

L</PSBT_MAGIC>, L</PSBT_SEPARATOR>, L</PSBT_GLOBAL_MAP>, L</PSBT_INPUT_MAP>, L</PSBT_OUTPUT_MAP>

=head2 :bech32

Contains values useful for BECH32:

L</BECH32>, L</BECH32M>

=head1 CONSTANTS

=head2 CURVE_NAME

Curve name used by Bitcoin, C<secp256k1>

=head2 CURVE_ORDER

A bytestring containing the secp256k1 curve order.

=head2 CURVE_GENERATOR

A bytestring with serialized uncompressed curve generator point for secp256k1.

=head2 MAX_CHILD_KEYS

Maximum number of keys which can be derived in extended key derivation. Values
above it start being recognized as hardened instead, and start counting from 0.

=head2 KEY_MAX_LENGTH

The maximum byte length of a serialized private key.

=head2 WIF_COMPRESSED_BYTE

A magic byte which is used in WIFs to mark the key as compressed.

=head2 SEGWIT_WITNESS_VERSION

Numeric witness version used in SegWit (version 0) programs.

=head2 TAPROOT_WITNESS_VERSION

Numeric witness version used in Taproot (version 1) programs.

=head2 MAX_WITNESS_VERSION

Numeric maximum possible witness version.

=head2 BIP44_PURPOSE

Numeric base BIP44 purpose.

=head2 BIP44_COMPAT_PURPOSE

Numeric BIP44 compat SegWit purpose (BIP49)

=head2 BIP44_SEGWIT_PURPOSE

Numeric BIP44 native SegWit purpose (BIP84)

=head2 BIP44_TAPROOT_PURPOSE

Numeric BIP44 native SegWit purpose (BIP86)

=head2 UNITS_PER_COIN

Number of satoshis that equal a single coin.

=head2 MAX_MONEY

Number of satoshis that will ever exist.

=head2 LOCKTIME_HEIGHT_THRESHOLD

First number which will be understood as timestamp in locktime checks.

=head2 MAX_SEQUENCE_NO

Default and maximum possible L<Bitcoin::Crypto::Transaction::Input/sequence_no>.

=head2 RBF_SEQUENCE_NO_THRESHOLD

Value which is used in finding out if a transaction has Replace-By-Fee enabled.

=head2 NULL_UTXO

An 2-element array reference which is an UTXO location for a coinbase transaction.

=head2 SIGHASH_DEFAULT

Default hashtype for digests - only used in Taproot. Functionally equal to SIGHASH_ALL.

=head2 SIGHASH_ALL

Hashtype for digesting all outputs of a transaction - default in pre-Taproot.

=head2 SIGHASH_NONE

Hashtype for digesting no transaction outputs.

=head2 SIGHASH_SINGLE

Hashtype for digesting only one output in a transaction, corresponding to this input.

=head2 SIGHASH_ANYONECANPAY

Hashtype for digesting only this input and no other inputs. Cannot be used
standalone, must be binary-or'ed with other SIGHASH constants.

=head2 SCRIPT_MAX_STACK_ELEMENTS

Maximum number of elements which can be kept on a script stack and altstack
together.

=head2 SCRIPT_MAX_ELEMENT_SIZE

Maximum byte size of a single stack element.

=head2 SCRIPT_MAX_OPCODES

Maximum non-push opcodes which can be used in a single script. Not applicable
to Taproot.

=head2 SCRIPT_MAX_SIZE

Maximum script size in bytes. Not applicable to Taproot.

=head2 SCRIPT_MAX_MULTISIG_PUBKEYS

Maximum OP_CHECKMULTISIG public keys.

=head2 TAPSCRIPT_LEAF_VERSION

Tree leaf version number used in Taproot tapscript spends.

=head2 PSBT_MAGIC

A magic byte sequence which is required in PSBTs.

=head2 PSBT_SEPARATOR

A byte sequence which separates PSBT maps.

=head2 PSBT_GLOBAL_MAP

A value for making use of global PSBT maps.

=head2 PSBT_INPUT_MAP

A value for making use of input PSBT maps.

=head2 PSBT_OUTPUT_MAP

A value for making use of output PSBT maps.

=head2 BECH32

A value used for marking original bech32 serialization

=head2 BECH32M

A value used for marking bech32m serialization

=head2 USE_BIGINTS

Whether the module currently uses BigInts (32-bit architecture compatibility).
Can be forced to a true value by setting C<BITCOIN_CRYPTO_USE_BIGINTS>
environmental variable.

=head2

