package Bitcoin::Crypto::Transaction::ControlBlock;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;

use Bitcoin::Crypto qw(btc_pub);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Util qw(lift_x);

has param 'control_byte' => (
	isa => IntMaxBits [8],
);

has param 'public_key' => (
	isa => InstanceOf ['Bitcoin::Crypto::Key::Public'],
);

has param 'script_blocks' => (
	coerce => (ArrayRef [ByteStrLen [32]])
		->where(q{ @$_ <= 128 }),
);

signature_for from_serialized => (
	method => Str,
	positional => [ByteStr],
);

sub from_serialized
{
	my ($class, $control_block) = @_;

	my ($control_byte, $xonly_pub, @script_blocks) = grep { length } unpack 'Ca32(a32)*', $control_block;

	return $class->new(
		control_byte => $control_byte,
		public_key => btc_pub->from_serialized(lift_x $xonly_pub),
		script_blocks => \@script_blocks,
	);
}

signature_for to_serialized => (
	method => Object,
	positional => [],
);

sub to_serialized
{
	my ($self) = @_;

	return pack('C', $self->control_byte)
		. $self->public_key->get_xonly_key
		. join '', @{$self->script_blocks};
}

signature_for get_leaf_version => (
	method => Object,
	positional => [],
);

sub get_leaf_version
{
	my ($self) = @_;

	return $self->control_byte & 0xfe;
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Transaction::ControlBlock - BIP341 Control blocks

=head1 SYNOPSIS

	# get control block from Bitcoin::Crypto::Script::Tree and $public_key
	# (tree must have a leaf with id => $leaf_id)
	my $control_block = $tree->get_control_block($leaf_id, $public_key);

	# get serialized form of the control block (used in taproot script path spending)
	$control_block->to_serialized;

=head1 DESCRIPTION

This module contains implementation of control blocks described in
L<BIP341|https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>. These
blocks are used by taproot and are necessary to build transactions using custom
taproot scripts. Taproot outputs spent by scripts must have a serialized
control block in their witness data (after the serialized script leaf data).

=head1 INTERFACE

=head2 Attributes

=head3 control_byte

B<Required in constructor.>

This attribute contains a control byte in form of an integer.

=head3 public_key

B<Required in constructor.>

This attribute contains an instance of L<Bitcoin::Crypto::Key::Public>.

=head3 script_blocks

B<Required in constructor.>

This attribute contains an array reference of bytestrings. It represents a path
to build a merkle root for a tree. These blocks can be used in
L<Bitcoin::Crypto::Script::Tree/from_path>.

=head2 METHODS

=head3 new

	$tree = $class->new(%args)

Standard Moo constructor - see L</Attributes>.

=head3 from_serialized

	$object = $class->from_serialized($bytestr)

Standard deserialization method. Returns a new instance.

=head3 to_serialized

	$bytestr = $object->to_serialized()

Standard serialization method.

=head3 get_leaf_version

	$leaf_version = $object->get_leaf_version()

Returns a leaf version, which is equal to C<control_byte & 0xfe>.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Script::Tree>

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

