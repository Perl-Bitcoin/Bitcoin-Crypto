package Bitcoin::Crypto::Script::Tree;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Util qw(tagged_hash pack_compactsize has_even_y);

use namespace::clean;

# recursive structure - a binary tree
has param 'tree' => (
	isa => ArrayRef [ArrayRef | HashRef],
);

sub _traverse
{
	my ($self, $script_tree, $join_action, $leaf_action) = @_;

	my @result;
	foreach my $item (@$script_tree) {
		if (ref $item eq 'ARRAY') {

			# this value is the next level of the tree
			push @result, $self->_traverse($item, $join_action, $leaf_action);
		}
		else {
			state $precomputed_type = Dict [hash => ByteStr];
			state $leaf_type = Dict [leaf_version => IntMaxBits [8], script => BitcoinScript, id => Optional [Int]];

			# this value is a leaf which may need calculating
			my $value = $precomputed_type->coerce($item);
			if (!$precomputed_type->check($value)) {
				$value = $leaf_type->assert_coerce($item);
				my $script = $value->{script}->to_serialized;
				my $script_len = pack_compactsize(length $script);

				$value->{hash} =
					tagged_hash('TapLeaf', join '', pack('C', $value->{leaf_version}), $script_len, $script);
			}

			$leaf_action->($value) if defined $leaf_action;
			push @result, $value;
		}
	}

	if (@result == 2) {

		# sort result so that smaller hash values come first
		@result = reverse @result
			if $result[0]->{hash} gt $result[1]->{hash};

		my %data = defined $join_action ? $join_action->(@result) : ();
		return {
			%data,
			hash => tagged_hash('TapBranch', join '', map { $_->{hash} } @result),
		};
	}
	elsif (@result == 1) {
		return $result[0];
	}

	Bitcoin::Crypto::Exception->raise(
		'invalid taproot script tree, not a binary tree'
	);
}

sub _tree_paths_action
{
	my ($self) = @_;

	my %paths;
	my $action = sub {
		my ($node1, $node2) = @_;
		my @all_ids;

		foreach my $info ([$node1, $node2], [$node2, $node1]) {
			my ($this_one, $other_one) = @{$info};
			next unless defined $this_one->{id};
			my @ids = ref $this_one->{id} ? @{$this_one->{id}} : $this_one->{id};
			push @all_ids, @ids;

			foreach my $id (@ids) {
				push @{$paths{$id}}, $other_one->{hash};
			}
		}

		return (
			id => \@all_ids,
		);
	};

	return (\%paths, $action);
}

sub _find_leaf_action
{
	my ($self, $id) = @_;

	my $leaf;
	my $action = sub {
		return if defined $leaf;

		my ($node) = @_;

		$leaf = $node
			if defined $node->{id} && $node->{id} == $id;
	};

	return (\$leaf, $action);
}

signature_for get_merkle_root => (
	method => Object,
	positional => [],
);

sub get_merkle_root
{
	my ($self) = @_;

	my $result = $self->_traverse($self->tree);
	return $result->{hash};
}

signature_for get_tree_paths => (
	method => Object,
	positional => [],
);

sub get_tree_paths
{
	my ($self) = @_;
	my ($paths, $action) = $self->_tree_paths_action;

	my $result = $self->_traverse($self->tree, $action);

	return $paths;
}

signature_for from_structure => (
	method => Str,
	positional => [ArrayRef],
);

sub from_structure
{
	my ($class, $tree) = @_;

	return $class->new(tree => $tree);
}

signature_for from_path => (
	method => Str,
	positional => [HashRef, ArrayRef [ByteStr]],
);

sub from_path
{
	my ($class, $leaf, $path) = @_;

	my @path = @$path;
	while (@path) {
		my $this_level = [$leaf, {hash => shift @path}];
		$leaf = $this_level;
	}

	return $class->new(
		tree => $leaf
	);
}

signature_for get_control_block => (
	method => Object,
	positional => [Int, InstanceOf ['Bitcoin::Crypto::Key::Public']],
);

sub get_control_block
{
	my ($self, $leaf_id, $pubkey) = @_;

	my ($paths_ref, $paths_action) = $self->_tree_paths_action;
	my ($leaf_ref, $leaf_action) = $self->_find_leaf_action($leaf_id);

	$self->_traverse($self->tree, $paths_action, $leaf_action);

	Bitcoin::Crypto::Exception::ScriptTree->raise(
		"no such block with id=$leaf_id"
	) unless defined $$leaf_ref;

	my $tapkey = $pubkey->get_taproot_tweaked_key(tweak_suffix => $self->get_merkle_root);
	my $parity = has_even_y($tapkey);

	my $leaf_version = ${$leaf_ref}->{leaf_version} | !$parity;
	my $path = $paths_ref->{$leaf_id} // [];

	return pack('C', $leaf_version) . $pubkey->get_xonly_key . join '', @$path;
}

1;

__END__

=head2 taproot_merkle_root

	$hash = taproot_merkle_root($tree_data)

Calculates a merkle root of taproot script tree (array ref). Unlike
L</merkle_root>, this must be an actual binary tree structure:

	my $leaf1 = {
		hash => [hex => $block_hash1]
	};

	my $leaf2 = {
		hash => [hex => $block_hash2]
	};

	my $leaf3 = {
		leaf_version => 192,
		script => [hex => '20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac'],
	};

	[
		$leaf1,
		[
			$leaf2,
			$leaf3,
		]
	]

Each level of a tree must be an array reference with up to two values in it.
Each leaf must be a hash with either a prehashed value under C<hash> key
(bytestring or something which can be coerced into a bytestring) or a script to
be hashed represented by keys C<leaf_version> (integer up to 255) and C<script>
(an instance of L<Bitcoin::Crypto::Script> or something which can be coerced
into it).

Returns a bytestring which is the root hash of the tree.

