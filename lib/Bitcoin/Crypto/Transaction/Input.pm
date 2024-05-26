package Bitcoin::Crypto::Transaction::Input;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;
use Scalar::Util qw(blessed);
use Try::Tiny;

use Bitcoin::Crypto qw(btc_script btc_utxo);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Util qw(to_format pack_varint unpack_varint);
use Bitcoin::Crypto::Types
	qw(ByteStr Str IntMaxBits ArrayRef InstanceOf Object BitcoinScript Bool Defined ScalarRef PositiveOrZeroInt Tuple Maybe);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Script::Common;

use namespace::clean;

has param 'utxo_location' => (
	coerce => Tuple [ByteStr, PositiveOrZeroInt],
);

has option 'utxo' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction::UTXO'],
	lazy => 1,
);

has param 'signature_script' => (
	writer => 1,
	coerce => BitcoinScript,
	default => '',
);

has param 'sequence_no' => (
	isa => IntMaxBits [32],
	writer => 1,
	default => Bitcoin::Crypto::Constants::max_sequence_no,
);

has option 'witness' => (
	coerce => ArrayRef [ByteStr],
	writer => 1,
);

with qw(
	Bitcoin::Crypto::Role::ShallowClone
);

sub _nested_script
{
	my ($self) = @_;

	my $input_script = $self->signature_script->to_serialized;
	return undef unless length $input_script;

	my $push = substr $input_script, 0, 1, '';
	return undef unless ord $push == length $input_script;

	my $real_script = btc_script->from_serialized($input_script);
	return $real_script;
}

# script code for segwit digests (see script_base)
sub _script_code
{
	my ($self) = @_;
	my $utxo = $self->utxo;

	my $locking_script = $utxo->output->locking_script;
	my $program;
	my %types = (
		P2WPKH => sub {

			# get script hash from P2WPKH (ignore the first two OPs - version and push)
			my $hash = substr $locking_script->to_serialized, 2;
			$program = Bitcoin::Crypto::Script::Common->new(PKH => $hash);
		},
		P2WSH => sub {

			# TODO: this is not complete, as it does not take OP_CODESEPARATORs into account
			# NOTE: Transaction::Digest sets witness to signing_subscript
			$program = btc_script->from_serialized(($self->witness // [''])->[-1]);
		},
	);

	my $type = $utxo->output->locking_script->type;

	if ($type eq 'P2SH') {

		# nested - nothing should get here without checking if nested script is native segwit
		my $nested = $self->_nested_script;
		$type = $nested->type;

		$locking_script = $nested;
	}

	$types{$type}->();
	return $program;
}

sub _build_utxo
{
	my ($self) = @_;

	return btc_utxo->get(@{$self->utxo_location});
}

around BUILDARGS => sub {
	my ($orig, $class, @params) = @_;
	my %hash_params = @params;
	my $utxo = delete $hash_params{utxo};

	if ($utxo) {
		if (blessed $utxo && $utxo->isa('Bitcoin::Crypto::Transaction::UTXO')) {
			return {
				%hash_params,
				utxo => $utxo,
				utxo_location => [$utxo->txid, $utxo->output_index],
			};
		}
		elsif (ref $utxo eq 'ARRAY') {
			return {
				%hash_params,
				utxo_location => $utxo,
			};
		}
	}

	return $class->$orig(@params);
};

signature_for utxo_registered => (
	method => Object,
	positional => [],
);

sub utxo_registered
{
	my ($self) = @_;

	try { $self->utxo } unless $self->has_utxo;
	return $self->has_utxo;
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	# input should be serialized as follows:
	# - transaction hash, 32 bytes
	# - transaction output index, 4 bytes
	# - signature script length, 1-9 bytes
	# - signature script
	# - sequence number, 4 bytes
	my $serialized = '';

	$serialized .= $self->prevout;

	my $script = $self->signature_script->to_serialized;
	$serialized .= pack_varint(length $script);
	$serialized .= $script;

	$serialized .= pack 'V', $self->sequence_no;

	return $serialized;
}

signature_for from_serialized => (
	method => Str,
	head => [ByteStr],
	named => [
		pos => Maybe [ScalarRef [PositiveOrZeroInt]],
		{default => undef},
	],
	bless => !!0,
);

sub from_serialized
{
	my ($class, $serialized, $args) = @_;
	my $partial = !!$args->{pos};
	my $pos = $partial ? ${$args->{pos}} : 0;

	my $transaction_hash = scalar reverse substr $serialized, $pos, 32;
	$pos += 32;

	my $transaction_output_index = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	my $script_size = unpack_varint $serialized, \$pos;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized input script data is corrupted'
	) if $pos + $script_size > length $serialized;

	my $script = substr $serialized, $pos, $script_size;
	$pos += $script_size;

	my $sequence = unpack 'V', substr $serialized, $pos, 4;
	$pos += 4;

	Bitcoin::Crypto::Exception::Transaction->raise(
		'serialized input data is corrupted'
	) if !$partial && $pos != length $serialized;

	${$args->{pos}} = $pos
		if $partial;

	return $class->new(
		utxo => [$transaction_hash, $transaction_output_index],
		signature_script => $script,
		sequence_no => $sequence,
	);
}

signature_for is_segwit => (
	method => Object,
	positional => [],
);

sub is_segwit
{
	my ($self) = @_;

	# Determines whether this script is segwit (including nested variants).
	# There's no need to verify P2SH hash matching, as it will be checked at a
	# later stage. It's enough if the input promises the segwit format.

	my $output_script = $self->utxo->output->locking_script;
	return !!1 if $output_script->is_native_segwit;
	return !!0 unless ($output_script->type // '') eq 'P2SH';

	my $nested = $self->_nested_script;
	return !!0 unless defined $nested;
	return !!1 if $nested->is_native_segwit;

	return !!0;
}

signature_for prevout => (
	method => Object,
	positional => [],
);

sub prevout
{
	my ($self) = @_;
	my ($txid, $index) = @{$self->utxo_location};

	return scalar reverse($txid) . pack 'V', $index;
}

signature_for script_base => (
	method => Object,
	positional => [],
);

sub script_base
{
	my ($self) = @_;

	if ($self->is_segwit) {
		return $self->_script_code;
	}
	else {
		return $self->utxo->output->locking_script;
	}
}

signature_for dump => (
	method => Object,
	positional => [],
);

sub dump
{
	my ($self) = @_;

	my $utxo = $self->utxo_registered ? $self->utxo : undef;
	my $utxo_location = $self->utxo_location;

	my @result;

	if ($utxo) {
		my $type = $utxo->output->locking_script->type // 'Custom';
		my $address = $utxo->output->locking_script->get_address // '';
		$address = " from $address" if $address;
		push @result, "$type Input$address";
	}
	else {
		push @result, "Unknown Input (UTXO was not registered, data is incomplete)";
	}

	push @result, 'spending output #' . $utxo_location->[1] . ' from ' . to_format([hex => $utxo_location->[0]]);
	push @result, 'value: ' . $utxo->output->value
		if $utxo;
	push @result, sprintf 'sequence: 0x%X', $self->sequence_no;
	push @result, 'locking script: ' . to_format [hex => $utxo->output->locking_script->to_serialized]
		if $utxo;

	if (!$self->signature_script->is_empty) {
		push @result, 'signature script: ' . to_format [hex => $self->signature_script->to_serialized];
	}

	if ($self->has_witness) {
		push @result, 'witness: ';
		foreach my $witness (@{$self->witness}) {
			push @result, to_format [hex => $witness];
		}
	}

	return join "\n", @result;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Transaction::Input - Bitcoin transaction input instance

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_transaction);

	my $tx = btc_transaction->new;

	$tx->add_input(
		utxo => [$txid, $output_index],
	);

	print $tx->inputs->[0]->dump;


=head1 DESCRIPTION

This is an input instance implementation used in transactions. It is rarely
interacted with directly.

=head1 INTERFACE

=head2 Attributes

=head3 utxo

An instance of L<Bitcoin::Crypto::Transaction::UTXO>. Required.

Can also be passed an array reference of two parameters, which will be fed to
L<Bitcoin::Crypto::Transaction::UTXO/get> to fetch the UTXO instance. It will
be done lazily, so that you can freely deserialize transactions without the
need to set up their UTXOs.

I<Available in the constructor>.

=head3 utxo_location

An array reference with the same data as passed to
L<Bitcoin::Crypto::Transaction::UTXO/get>. Will be pulled out of whatever was
passed to L</utxo>.

=head3 signature_script

The script used to unlock the coins from the UTXO.

By default, it is an empty script.

I<Available in the constructor>.

I<writer>: C<set_signature_script>

=head3 sequence_no

Also known as C<nSequence> in Bitcoin Core. The sequence number used in various
applications. Non-negative integer.

By default, it is set to C<0xffffffff> (C<max_sequence_no> in C<Bitcoin::Crypto::Constants>).

I<Available in the constructor>.

I<writer>: C<set_sequence_no>

=head3 witness

SegWit data for this input. It is an array reference of bytestrings. Note that
each element in the witness must be a separate element in this array
(concatenating the witness into one bytestring will not work as intended).

Empty by default.

I<Available in the constructor>.

I<writer>: C<set_witness>

I<predicate>: C<has_witness>

=head2 Methods

=head3 new

	$block = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns class instance.

=head3 utxo_registered

	$boolean = $object->utxo_registered()

Returns boolean value indicating whether UTXO for this input is reachable. If
it isn't, getting L</utxo> will throw an exception.

Creating transactions without registered UTXOs will work in very basic cases
but can randomly throw C<Bitcoin::Crypto::Exception::UTXO> exception. It is
mainly useful for getting data encoded in a serialized transaction.

=head3 to_serialized

	$bytestring = $object->to_serialized()

Returns the serialized input data to be included into a serialized transaction.

NOTE: serialized input does not include witness data, which is a part of this class.

=head3 from_serialized

	$object = $class->from_serialized($bytestring, %params)

Creates an object instance from serialized data.

C<%params> can be any of:

=over

=item * C<pos>

Position for partial string decoding. Optional. If passed, must be a scalar
reference to an integer value.

This integer will mark the starting position of C<$bytestring> from which to
start decoding. It will be set to the next byte after end of input stream.

=back

=head3 is_segwit

	$boolean = $object->is_segwit()

Returns true if this input represents a segwit output.

For scripts which have C<signature_script> filled out, this method is able to
detect both native and compatibility segwit outputs (unlike
L<Bitcoin::Crypto::Script/is_native_segwit>).

=head3 prevout

	$bytestring = $object->prevout()

Returns a bytestring with prevout data ready to be encoded in places like
digest preimages. Mostly used internally.

=head3 script_base

	$script = $object->script_base()

Returns a base script for the digest. Mostly used internally.

=head3 dump

	$text = $object->dump()

Returns a readable description of the input.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * Transaction - general error with transaction

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=item L<Bitcoin::Crypto::Transaction::UTXO>

=back

=cut

