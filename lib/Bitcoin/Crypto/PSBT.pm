package Bitcoin::Crypto::PSBT;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;
use List::Util qw(any);
use Scalar::Util qw(blessed);

use Bitcoin::Crypto qw(btc_transaction btc_utxo);
use Bitcoin::Crypto::PSBT::Map;
use Bitcoin::Crypto::PSBT::Field;
use Bitcoin::Crypto::PSBT::FieldType;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Constants qw(:psbt);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Exception;

has param 'strict' => (
	isa => Bool,
	default => !!0,
	writer => 1,
);

has field 'maps' => (
	isa => ArrayRef [InstanceOf ['Bitcoin::Crypto::PSBT::Map']],
	default => sub { [] },
);

with qw(
	Bitcoin::Crypto::Role::PSBT::Signer
	Bitcoin::Crypto::Role::PSBT::Finalizer
);

sub _check_can_modify
{
	my ($self, $type, $index) = @_;

	return unless $type eq PSBT_INPUT_MAP || $type eq PSBT_OUTPUT_MAP;
	return unless $self->strict;

	my $count = $type eq PSBT_INPUT_MAP ? $self->input_count : $self->output_count;
	return unless $index >= $count;

	if ($self->version == 0) {
		Bitcoin::Crypto::Exception::PSBT->raise(
			"Cannot add a new map entry because index is out of range of PSBT_GLOBAL_UNSIGNED_TX ($count)"
		);
	}
	elsif ($self->version == 2) {
		my $modifiable = $self->get_all_fields('PSBT_GLOBAL_TX_MODIFIABLE');
		my $field_name = $type eq PSBT_INPUT_MAP ? 'inputs_modifiable' : 'outputs_modifiable';

		Bitcoin::Crypto::Exception::PSBT->raise(
			"Cannot add a new map entry because PSBT_GLOBAL_TX_MODIFIABLE ($field_name) is off"
		) unless $modifiable && $modifiable->value->{$field_name};
	}
}

sub _get_map
{
	my ($self, $maptype, %args) = @_;

	my $found_map;
	foreach my $map (@{$self->maps}) {
		next unless $map->type eq $maptype;
		next if $map->need_index && (!defined $args{index} || $map->index ne $args{index});

		$found_map = $map;
		last;
	}

	if (!$found_map && $args{set}) {
		$found_map = Bitcoin::Crypto::PSBT::Map::->new(
			type => $maptype,
			index => $args{index},
		);

		$self->_check_can_modify($found_map->type, $args{index})
			if $args{check};

		push @{$self->maps}, $found_map;
	}

	return $found_map;
}

sub input_count
{
	my ($self) = @_;
	my $version = $self->version;

	if ($version == 0) {
		my $tx = $self->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value;
		return scalar @{$tx->inputs};
	}
	elsif ($version == 2) {
		return $self->get_field('PSBT_GLOBAL_INPUT_COUNT')->value;
	}
}

sub output_count
{
	my ($self) = @_;
	my $version = $self->version;

	if ($version == 0) {
		my $tx = $self->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value;
		return scalar @{$tx->outputs};
	}
	elsif ($version == 2) {
		return $self->get_field('PSBT_GLOBAL_OUTPUT_COUNT')->value;
	}
}

signature_for get_field => (
	method => !!1,
	positional => [
		PSBTFieldType,
		Maybe [PositiveOrZeroInt], {default => undef},
		Maybe [ByteStr], {default => undef}
	],
);

sub get_field
{
	my ($self, $type, $index, $key) = @_;

	my @values = $self->get_all_fields($type, $index, $key);
	if (@values != 1) {
		my $id = $type->name;
		$id .= ", index $index" if defined $index;
		$id .= ', key ' . to_format [hex => $key] if defined $key;

		my $count = @values;

		Bitcoin::Crypto::Exception::PSBT->raise(
			"Could not get value for field $id: found $count values in PSBT"
		);
	}

	return $values[0];
}

signature_for get_all_fields => (
	method => !!1,
	positional => [
		PSBTFieldType,
		Maybe [PositiveOrZeroInt], {default => undef},
		Maybe [ByteStr], {default => undef}
	],
);

sub get_all_fields
{
	my ($self, $type, $index, $key) = @_;

	my $map = $self->_get_map($type->map_type, index => $index);
	return () unless $map;
	return $map->find($type, $key);
}

sub add_field
{
	my ($self, @data) = @_;
	my $field;
	my $index;

	if ((@data == 1 || @data == 2) && blessed $data[0] && $data[0]->isa('Bitcoin::Crypto::PSBT::Field')) {
		($field, $index) = @data;
	}
	else {
		my %data = @data;
		$index = delete $data{index};
		$field = Bitcoin::Crypto::PSBT::Field->new(%data);
	}

	my $map = $self->_get_map($field->type->map_type, index => $index, set => !!1, check => !!1);
	$map->add($field);

	return $self;
}

sub list_fields
{
	my ($self) = @_;

	my @results;
	foreach my $map (@{$self->maps}) {
		my $index = $map->index;
		my %seen;

		foreach my $field (@{$map->fields}) {
			next if $seen{$field->type->code}++;

			push @results, [$field->type, $index];
		}
	}

	# force list context to have same UI as get_all_fields
	return @results[0 .. $#results];
}

sub version
{
	my ($self) = @_;

	my $version = $self->get_all_fields('PSBT_GLOBAL_VERSION');
	$version = $version ? $version->value : 0;

	Bitcoin::Crypto::Exception::PSBT->raise(
		"PSBT version $version is not supported"
	) unless any { $_ == $version } 0, 2;

	return $version;
}

signature_for from_serialized => (
	method => !!1,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $serialized) = @_;
	my $self = $class->new;

	my $pos = length PSBT_MAGIC;
	my $magic = substr $serialized, 0, $pos;

	Bitcoin::Crypto::Exception::PSBT->raise(
		'serialized string does not contain the PSBT header'
	) unless $magic eq PSBT_MAGIC;

	push @{$self->maps}, Bitcoin::Crypto::PSBT::Map::->from_serialized(
		$serialized,
		map_type => PSBT_GLOBAL_MAP,
		pos => \$pos,
	);

	foreach my $index (0 .. $self->input_count - 1) {
		push @{$self->maps}, Bitcoin::Crypto::PSBT::Map::->from_serialized(
			$serialized,
			map_type => PSBT_INPUT_MAP,
			pos => \$pos,
			index => $index,
		);
	}

	foreach my $index (0 .. $self->output_count - 1) {
		push @{$self->maps}, Bitcoin::Crypto::PSBT::Map::->from_serialized(
			$serialized,
			map_type => PSBT_OUTPUT_MAP,
			pos => \$pos,
			index => $index,
		);
	}

	Bitcoin::Crypto::Exception::PSBT->raise(
		'serialized PSBT data is corrupted'
	) if $pos != length $serialized;

	$self->check;

	return $self;
}

sub to_serialized
{
	my ($self) = @_;

	$self->check;

	my $serialized = PSBT_MAGIC;
	$serialized .= $self->_get_map(PSBT_GLOBAL_MAP, set => !!1)->to_serialized;

	for my $input_index (0 .. $self->input_count - 1) {
		$serialized .= $self->_get_map(PSBT_INPUT_MAP, index => $input_index, set => !!1)
			->to_serialized;
	}

	for my $output_index (0 .. $self->output_count - 1) {
		$serialized .= $self->_get_map(PSBT_OUTPUT_MAP, index => $output_index, set => !!1)
			->to_serialized;
	}

	return $serialized;
}

sub check
{
	my ($self) = @_;
	my $version = $self->version;
	my $input_count = $self->input_count;
	my $output_count = $self->output_count;

	my $required_fields = Bitcoin::Crypto::PSBT::FieldType->get_fields_required_in_version($version);
	foreach my $field_type (@{$required_fields}) {
		my @maps;

		if ($field_type->map_type eq PSBT_GLOBAL_MAP) {
			@maps = ($self->_get_map($field_type->map_type));
		}
		elsif ($field_type->map_type eq PSBT_INPUT_MAP) {
			@maps = map { $self->_get_map($field_type->map_type, index => $_) } 0 .. $input_count - 1;
		}
		elsif ($field_type->map_type eq PSBT_OUTPUT_MAP) {
			@maps = map { $self->_get_map($field_type->map_type, index => $_) } 0 .. $output_count - 1;
		}

		foreach my $map (@maps) {
			my @values = defined $map ? $map->find($field_type) : ();
			Bitcoin::Crypto::Exception::PSBT->raise(
				"PSBT field " . $field_type->name . " is required in version $version"
			) unless @values == 1;
		}
	}

	foreach my $map (@{$self->maps}) {

		if ($map->type eq PSBT_INPUT_MAP) {
			Bitcoin::Crypto::Exception::PSBT->raise(
				"PSBT input map index " . $map->index . " out of range"
			) unless $map->index < $input_count;
		}
		elsif ($map->type eq PSBT_OUTPUT_MAP) {
			Bitcoin::Crypto::Exception::PSBT->raise(
				"PSBT output map index " . $map->index . " out of range"
			) unless $map->index < $output_count;
		}

		foreach my $field (@{$map->fields}) {
			Bitcoin::Crypto::Exception::PSBT->raise(
				"PSBT field " . $field->type->name . " is not available in version $version"
			) unless $field->type->available_in_version($version);
		}
	}

	return $self;
}

sub get_locktime
{
	my ($self) = @_;
	my $version = $self->version;

	if ($version == 0) {
		return $self->get_transaction->locktime;
	}
	elsif ($version == 2) {

		# NOTE: this logic is based on:
		# https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time

		my $time_locktimes = 0;
		my $height_locktimes = 0;
		my $max_time_locktime = 0;
		my $max_height_locktime = 0;

		foreach my $input_index (0 .. $self->input_count - 1) {
			my $time = $self->get_all_fields('PSBT_IN_REQUIRED_TIME_LOCKTIME', $input_index);
			my $height = $self->get_all_fields('PSBT_IN_REQUIRED_HEIGHT_LOCKTIME', $input_index);

			$time_locktimes += defined $time;
			$height_locktimes += defined $height;

			$max_time_locktime = $time->value
				if $time && $time->value > $max_time_locktime;
			$max_height_locktime = $height->value
				if $height && $height->value > $max_height_locktime;
		}

		if ($time_locktimes > 0 && $height_locktimes > 0) {
			if ($time_locktimes == $self->input_count && $time_locktimes > $height_locktimes) {
				return $max_time_locktime;
			}
			else {
				return $max_height_locktime;
			}
		}
		elsif ($time_locktimes > $height_locktimes) {
			return $max_time_locktime;
		}
		elsif ($height_locktimes > $time_locktimes) {
			return $max_height_locktime;
		}
		else {
			my $fallback = $self->get_all_fields('PSBT_GLOBAL_FALLBACK_LOCKTIME');

			return $fallback ? $fallback->value : 0;
		}
	}
}

sub _get_utxo
{
	my ($self, $input_index, $txid, $output_index) = @_;

	my $non_witness_utxo = $self->get_all_fields('PSBT_IN_NON_WITNESS_UTXO', $input_index);
	my $witness_utxo = $self->get_all_fields('PSBT_IN_WITNESS_UTXO', $input_index);

	return unless $non_witness_utxo || $witness_utxo;

	my $output;

	if ($non_witness_utxo) {
		my $utxo_tx = $non_witness_utxo->value;

		Bitcoin::Crypto::Exception::PSBT->raise(
			'invalid PSBT_IN_NON_WITNESS_UTXO - txid mismatch'
		) unless $utxo_tx->txid eq $txid;

		Bitcoin::Crypto::Exception::PSBT->raise(
			"invalid PSBT_IN_NON_WITNESS_UTXO - no output $output_index"
		) unless defined $utxo_tx->outputs->[$output_index];

		$output = $utxo_tx->outputs->[$output_index];
	}
	elsif ($witness_utxo) {
		$output = $witness_utxo->value;
	}

	return btc_utxo->new(
		txid => $txid,
		output_index => $output_index,
		output => $output,
	);
}

sub get_transaction
{
	my ($self) = @_;

	$self->check;
	my $version = $self->version;

	my $tx;
	if ($version == 0) {
		$tx = $self->get_field('PSBT_GLOBAL_UNSIGNED_TX')->value;
	}
	elsif ($version == 2) {
		$tx = btc_transaction->new(
			version => $self->get_field('PSBT_GLOBAL_TX_VERSION')->value,
			locktime => $self->get_locktime,
		);

		foreach my $input_index (0 .. $self->input_count - 1) {
			my $utxo_txid = $self->get_field('PSBT_IN_PREVIOUS_TXID', $input_index)->value;
			my $utxo_output = $self->get_field('PSBT_IN_OUTPUT_INDEX', $input_index)->value;
			my $sequence_field = $self->get_all_fields('PSBT_IN_SEQUENCE', $input_index);

			$tx->add_input(
				utxo => [$utxo_txid, $utxo_output],
				(defined $sequence_field ? (sequence_no => $sequence_field->value) : ()),
			);
		}

		foreach my $output_index (0 .. $self->output_count - 1) {
			my $value = $self->get_field('PSBT_OUT_AMOUNT', $output_index)->value;
			my $script = $self->get_field('PSBT_OUT_SCRIPT', $output_index)->value;

			$tx->add_output(
				locking_script => $script,
				value => $value,
			);
		}
	}

	foreach my $input_index (0 .. $self->input_count - 1) {
		my $input = $tx->inputs->[$input_index];

		# try to fill utxos - if not present in the PSBT, fallback to simply
		# leaving the basic UTXO information as they are. UTXO will not be
		# registered.
		my $utxo = $self->_get_utxo($input_index, @{$input->utxo_location});
		$input->set_utxo($utxo) if $utxo;

		# fill signatures
		my $signature_field = $self->get_all_fields('PSBT_IN_FINAL_SCRIPTSIG', $input_index);
		my $witness_field = $self->get_all_fields('PSBT_IN_FINAL_SCRIPTWITNESS', $input_index);

		$input->set_signature_script($signature_field->value)
			if $signature_field;

		$input->set_witness($witness_field->value)
			if $witness_field;
	}

	return $tx;
}

sub dump
{
	my ($self) = @_;
	my @result;

	my @maps = sort {
		my $ret = $a->type cmp $b->type;
		if ($ret == 0 && $a->need_index) {
			$ret = $a->index <=> $b->index;
		}

		$ret;
	} @{$self->maps};

	foreach my $map (@maps) {
		push @result, $map->name . ' map:';

		my $dumped = $map->dump;
		push @result, $dumped
			if length $dumped;
	}

	return join "\n", @result;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::PSBT - Partially Signed Bitcoin Transactions

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_psbt);

	# import PSBT from a serialized form
	my $psbt = btc_psbt->from_serialized([base64 => $psbt_string]);

	# dump in readable format
	print $psbt->dump;

	# get a single PSBT field
	my $field = $psbt->get_field('PSBT_GLOBAL_TX_VERSION');

	# get decoded field key and value
	my $key = $field->key;
	my $value = $field->value;

	# get all PSBT fields of a given type
	my @fields = $psbt->get_all_fields('PSBT_GLOBAL_PROPRIETARY');

=head1 DESCRIPTION

This is a class implementing the PSBT format as described in BIP174 and
BIP370. It currently supports versions 0 and 2 of the spec. It allows
serialization, deserialization, validation and access to PSBT fields. It
currently does not support the roles defined by the PSBT documents, so all the
operations on PSBTs (like adding inputs or creating a final transaction out of
it) must be done manually.

PSBT consists of a number of maps: one global, one for each transaction input
and one for each transaction output. Each map holds a number of fields. Each
field has a value and can optionally have extra key data.

=head1 INTERFACE

=head2 Attributes

=head3 strict

Optional boolean flag, which is false by default. If set to true, enables some
extra checks while modifying the PSBT (before L</check> is called). The checks
are:

=over

=item

For PSBTs version 0, disallows adding new input and output maps via
L</add_field> unless C<PSBT_GLOBAL_UNSIGNED_TX> contains this input or output
index.

=item

For PSBTs version 2, disallows adding new input and output maps via
L</add_field> if not allowed by the state of C<PSBT_GLOBAL_TX_MODIFIABLE>
field.

=back

I<writer>: C<set_strict>

=head3 maps

B<Not assignable in the constructor>

An array reference of PSBT internal maps - objects of class
L<Bitcoin::Crypto::PSBT::Map>. It should seldom be handled manually - use
L</get_field>, L</get_all_fields> and L</add_field> to access fields of
specific map.

=head2 Methods

=head3 new

	$psbt = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object.

Returns class instance.

=head3 version

	$version = $object->version()

Returns the version of the PSBT (C<0> or C<2>).

=head3 input_count

	$int = $object->input_count()

Returns the number of inputs the PSBT defines.

=head3 output_count

	$int = $object->output_count()

Returns the number of outputs the PSBT defines.

=head3 get_field

	$field = $object->get_field($field_type_name, $map_index = undef, $key = undef)

Tries to get a field of C<$field_type_name> as defined in BIP174, for example
C<PSBT_GLOBAL_UNSIGNED_TX>. If the field is from input or output maps, it also
requires C<$map_index> to be passed (0-based index of the input or output).
Optional C<$key> (a bytestring) can be provided if this PSBT field defines keys.

Returns an instance of L<Bitcoin::Crypto::PSBT::Field>, which you can use to
access key and value data.

If there isn't exactly one field with this type in the map, it will throw an
exception. This allows you to write the following without checking the return
value of the function:

	my $output_index_0 = $object->get_field('PSBT_IN_OUTPUT_INDEX', 0)->value;

See L</get_all_fields> for a variant which does not check the field count.

=head3 get_all_fields

	@fields = $object->get_all_fields($field_type_name, $map_index = undef, $key = undef)

Same as L</get_field>, but will return all the fields of given type from a
given map. It may be used if the field exists, or to get multiple fields with
different key data.

The return value is a list (not an array), so using it in scalar context will
get the last found field (as opposed to a field count).

=head3 add_field

	$object = $object->add_field(%field_data)
	$object = $object->add_field($field_object, $map_index = undef)

Adds a new field to the PSBT. It can be run either with C<%field_data> (a hash
arguments for the L<Bitcoin::Crypto::PSBT::Field/new>) or with C<$field_object>
(constructed L<Bitcoin::Crypto::PSBT::Field>) and C<$map_index>.

If a map with C<$map_index> does not exist, it will be created. However, when
doing so, other information like the input or output count must be updated
manually.

If passing C<%field_data> hash, it can contain an additional C<index> key to
represent C<$map_index>. The field will be constructed and added to the map.
Adding the index to a map triggers its validations, so it must be complete
enough to pass them. For this reason, sometimes it could be more preferable to
construct and fill the field by hand before adding it to the PSBT.

Note that a field cannot be used in more than one map at a time.

=head3 list_fields

	@list = $object->list_fields()

This method lists all fields present in the PSBT. It returns a list of array
references, each array reference has two elements: field type and map index.
These are the same elements that are needed in L</get_all_fields> calls, so you
may use this data to loop through PSBT fields.

=head3 check

	$object = $object->check()

Checks the internal state of PSBT fields and throws an exception if it is
invalid. Returns the object itself.

=head3 get_locktime

	$int = $object->get_locktime()

Returns the locktime encoded in the PSBT as an integer. For version 0 PSBTs,
this simply returns the locktime in the unsigned transaction field. For version
2, it follows L<procedure described in
BIP370|https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time>.

Time or height-based threshold can be determined by comparing the result with
L<Bitcoin::Crypto::Constants/LOCKTIME_HEIGHT_THRESHOLD>.

=head3 get_transaction

	$transaction = $object->get_transaction()

Builds a new L<Bitcoin::Crypto::Transaction> object based on the contents of the PSBT.

If UTXO fields in the PSBT are populated, then the resulting transaction inputs
will have proper UTXOs set. However, those UTXOs will not be registered
globally, and will only be available to this transaction only.

=head3 to_serialized

	$serialized = $object->to_serialized()

Serializes a PSBT into a bytestring. L</check> is called automatically before
serializing.

=head3 from_serialized

	$object = $class->from_serialized($data)

Deserializes the bytestring C<$data> into a PSBT object. L</check> is called
automatically after deserializing.

=head3 dump

	$text = $object->dump()

Returns a readable description of all the maps in the PSBT.

=head1 FIELD REFERENCE

Just for reference, here is a list of all PSBT fields which are currently
supported by this module. This list is auto-generated from
L<Bitcoin::Crypto::PSBT::FieldType/key_data> and
L<Bitcoin::Crypto::PSBT::FieldType/value_data> (which contain short strings
with description of field content).

For a list of PSBT fields, see
L<BIP174|https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki> and
follow-up BIPS, most notably
L<BIP370|https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki> and
L<BIP371|https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki>.

=head2 Global map

=over

=item * PSBT_GLOBAL_UNSIGNED_TX

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Transaction object

=item * PSBT_GLOBAL_XPUB

B<Key data:> Bitcoin::Crypto::Key::ExtPublic object

B<Value data:> Array reference, where the first item is a fingerprint and the second item is Bitcoin::Crypto::DerivationPath

=item * PSBT_GLOBAL_TX_VERSION

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_GLOBAL_FALLBACK_LOCKTIME

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_GLOBAL_INPUT_COUNT

B<Key data:> <none>

B<Value data:> Positive integer value

=item * PSBT_GLOBAL_OUTPUT_COUNT

B<Key data:> <none>

B<Value data:> Positive integer value

=item * PSBT_GLOBAL_TX_MODIFIABLE

B<Key data:> <none>

B<Value data:> Hash reference with flags: inputs_modifiable, outputs_modifiable, has_sighash_single

=item * PSBT_GLOBAL_VERSION

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_GLOBAL_PROPRIETARY

B<Key data:> Array reference with three items: bytestring, unsigned integer, bytestring

B<Value data:> Bytestring value

=back

=head2 Input map

=over

=item * PSBT_IN_NON_WITNESS_UTXO

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Transaction object

=item * PSBT_IN_WITNESS_UTXO

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Transaction::Output object

=item * PSBT_IN_PARTIAL_SIG

B<Key data:> Bitcoin::Crypto::Key::Public object

B<Value data:> Bytestring value

=item * PSBT_IN_SIGHASH_TYPE

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_IN_REDEEM_SCRIPT

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Script object

=item * PSBT_IN_WITNESS_SCRIPT

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Script object

=item * PSBT_IN_BIP32_DERIVATION

B<Key data:> Bitcoin::Crypto::Key::Public object

B<Value data:> Array reference, where the first item is a fingerprint and the second item is Bitcoin::Crypto::DerivationPath

=item * PSBT_IN_FINAL_SCRIPTSIG

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Script object

=item * PSBT_IN_FINAL_SCRIPTWITNESS

B<Key data:> <none>

B<Value data:> Array reference, representing witness stack

=item * PSBT_IN_POR_COMMITMENT

B<Key data:> <none>

B<Value data:> Bytestring value

=item * PSBT_IN_RIPEMD160

B<Key data:> Bytestring value

B<Value data:> Bytestring value

=item * PSBT_IN_SHA256

B<Key data:> Bytestring value

B<Value data:> Bytestring value

=item * PSBT_IN_HASH160

B<Key data:> Bytestring value

B<Value data:> Bytestring value

=item * PSBT_IN_HASH256

B<Key data:> Bytestring value

B<Value data:> Bytestring value

=item * PSBT_IN_PREVIOUS_TXID

B<Key data:> <none>

B<Value data:> Bytestring value

=item * PSBT_IN_OUTPUT_INDEX

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_IN_SEQUENCE

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_IN_REQUIRED_TIME_LOCKTIME

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_IN_REQUIRED_HEIGHT_LOCKTIME

B<Key data:> <none>

B<Value data:> 32-bit positive integer value

=item * PSBT_IN_TAP_KEY_SIG

B<Key data:> <none>

B<Value data:> Bytestring value

=item * PSBT_IN_TAP_SCRIPT_SIG

B<Key data:> Array reference, where the first item is Bitcoin::Crypto::Key::Public and second element is a leaf hash bytestring

B<Value data:> Bytestring value

=item * PSBT_IN_TAP_LEAF_SCRIPT

B<Key data:> Instance of Bitcoin::Crypto::Transaction::ControlBlock

B<Value data:> Instance of Bitcoin::Crypto::Script::Tree::Leaf (with script and leaf version)

=item * PSBT_IN_TAP_BIP32_DERIVATION

B<Key data:> Bitcoin::Crypto::Key::Public object

B<Value data:> Array reference, where first item is an array of leaf hashes, second element is a fingerprint and the third element is Bitcoin::Crypto::DerivationPath

=item * PSBT_IN_TAP_INTERNAL_KEY

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Key::Public object

=item * PSBT_IN_TAP_MERKLE_ROOT

B<Key data:> <none>

B<Value data:> Bytestring value

=item * PSBT_IN_PROPRIETARY

B<Key data:> Array reference with three items: bytestring, unsigned integer, bytestring

B<Value data:> Bytestring value

=back

=head2 Output map

=over

=item * PSBT_OUT_REDEEM_SCRIPT

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Script object

=item * PSBT_OUT_WITNESS_SCRIPT

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Script object

=item * PSBT_OUT_BIP32_DERIVATION

B<Key data:> Bitcoin::Crypto::Key::Public object

B<Value data:> Array reference, where the first item is a fingerprint and the second item is Bitcoin::Crypto::DerivationPath

=item * PSBT_OUT_AMOUNT

B<Key data:> <none>

B<Value data:> 64 bit number

=item * PSBT_OUT_SCRIPT

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Script object

=item * PSBT_OUT_TAP_INTERNAL_KEY

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Key::Public object

=item * PSBT_OUT_TAP_TREE

B<Key data:> <none>

B<Value data:> Bitcoin::Crypto::Script::Tree instance

=item * PSBT_OUT_TAP_BIP32_DERIVATION

B<Key data:> Bitcoin::Crypto::Key::Public object

B<Value data:> Array reference, where first item is an array of leaf hashes, second element is a fingerprint and the third element is Bitcoin::Crypto::DerivationPath

=item * PSBT_OUT_PROPRIETARY

B<Key data:> Array reference with three items: bytestring, unsigned integer, bytestring

B<Value data:> Bytestring value

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::PSBT::Field>

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

