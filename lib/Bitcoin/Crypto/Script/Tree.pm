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

has field '_tree_cache' => (
	lazy => 1,
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

sub _build_tree_cache
{
	my ($self) = @_;

	my @leaves;
	my $root = $self->_traverse(
		$self->tree,
		undef,
		sub {
			my $leaf = shift;
			push @leaves, $leaf;
		}
	);

	return {
		leaves => \@leaves,
		root => $root,
	};
}

signature_for get_merkle_root => (
	method => Object,
	positional => [],
);

sub get_merkle_root
{
	my ($self) = @_;

	return $self->_tree_cache->{root}{hash};
}

signature_for get_tapleaf_hash => (
	method => Object,
	positional => [Int],
);

sub get_tapleaf_hash
{
	my ($self, $leaf_id) = @_;

	my @leaves = grep { exists $_->{id} && $_->{id} == $leaf_id } @{$self->_tree_cache->{leaves}};
	my $leaf = shift @leaves;

	Bitcoin::Crypto::Exception::ScriptTree->raise(
		"no such block with id=$leaf_id"
	) unless defined $leaf;

	return $leaf->{hash};
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

	$leaf = [$leaf]
		unless ref $leaf eq 'ARRAY';

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

	my $root = $self->_traverse($self->tree, $paths_action, $leaf_action);

	Bitcoin::Crypto::Exception::ScriptTree->raise(
		"no such block with id=$leaf_id"
	) unless defined $$leaf_ref;

	my $tapkey = $pubkey->get_taproot_tweaked_key(tweak_suffix => $root->{hash});
	my $parity = has_even_y($tapkey);

	my $leaf_version = ${$leaf_ref}->{leaf_version} | !$parity;
	my $path = $paths_ref->{$leaf_id} // [];

	return pack('C', $leaf_version) . $pubkey->get_xonly_key . join '', @$path;
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Script::Tree - BIP341 Script trees

=head1 SYNOPSIS

=head1 DESCRIPTION

This module contains implementation script trees described in
L<BIP341|https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>. These
trees are used by taproot and are necessary to build custom taproot scripts.

=head2 Tree leaves

Each leaf in the tree is represented with this Perl structure:

	{
		id => integer (optional),
		leaf_version => integer,
		script => Bitcoin::Crypto::Script instance (or its coercible),
	}

Optional C<id> is used to identify the leaf in the tree, which is used in
methods like L</get_control_block>.

If the leaf is prehashed or not known, it can be represented as this structure
instead:

	{
		hash => bytestring with prehashed leaf,
	}

=head1 METHODS

=head2 from_structure

	$tree = $class->from_structure($structure)

This static method builds a new C<$tree> object from structure C<$structure>.
This structure represents a binary tree and must contain an array reference of
array or hash references.

Each level of a tree must be an array reference with up to two values in it.
Each leaf must be a hash with either a prehashed value under C<hash> key
(bytestring or something which can be coerced into a bytestring) or a script to
be hashed represented by keys C<leaf_version> (integer up to 255) and C<script>
(an instance of L<Bitcoin::Crypto::Script> or something which can be coerced
into it).

Example structure:

	# tree with all scripts known
	[
		{
			id => 0,
			leaf_version => 192,
			script => [hex => '2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac']
		},
		[
			{
				id => 1,
				leaf_version => 192,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
			{
				id => 2,
				leaf_version => 192,
				script => [hex => '20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac']
			}
		]
	]

Each element may be prehashed, which represents the same tree, but without
disclosing information about a script:

	# same tree, but only one script is known and can be executed
	[
		{hash => [hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d']},
		[
			{
				leaf_version => 192,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
			{hash => [hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7']},
		]
	]

=head2 from_path

	$tree = $class->from_path($leaf, \@path)

This static method builds a new C<$tree> object from key path C<@path>. Key
path and represents a script tree by a series of prehashed leaves. C<$leaf> is
a tree leaf deserialized from transaction data.

C<@path> must only contain bytestrings or their coercibles. Example C<@path>
could look like this:

	(
		[hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7'],
		[hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d'],
	)

=head2 get_merkle_root

	$hash = $tree->get_merkle_root()

Calculates a merkle root of the script tree. Returns a bytestring which is the
root hash of the tree.

=head2 get_tapleaf_hash

	$hash = $tree->get_tapleaf_hash($leaf_id)

Calculates a tapleaf hash of a leaf with given C<$leaf_id>. If such leaf does
not exist, an exception is thrown. Returns a bytestring.

=head2 get_control_block

	$bytestr = $tree->get_control_block($leaf_id, $pubkey)

Builds a binary taproot control block used in taproot witness data. C<$leaf_id>
must be a valid identifier of a leaf existing in the tree. C<$pubkey> is a
public key that associated with the address for key path spending.

=head2 get_tree_paths

	$paths = $tree->get_tree_paths()

Returns a hash reference of paths for each of leaves in the tree which have an
id. Each path is an array reference - same as what L</from_path> takes as input.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * ScriptTree - general error with the tree

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Tapscript>

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

