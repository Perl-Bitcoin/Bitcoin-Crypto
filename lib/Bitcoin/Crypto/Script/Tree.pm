package Bitcoin::Crypto::Script::Tree;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;
use List::Util qw(first);
use Scalar::Util qw(blessed);
use Carp qw(carp);

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Util::Internal qw(tagged_hash pack_compactsize has_even_y);
use Bitcoin::Crypto::Script::Tree::Leaf;
use Bitcoin::Crypto::Transaction::ControlBlock;

# recursive structure - a binary tree
has param 'tree' => (
	isa => ArrayRef,
);

has field '_tree_cache' => (
	lazy => 1,
	clearer => -public,
);

# this is flat traversal algorithm that avoids deep recursion warnings in deep
# script trees
sub _traverse
{
	my ($self, $paths_ref, $leaves_ref) = @_;

	my @stack = ({nodes => [@{$self->tree}], results => []});
	my $result;

	while ('avoiding recursion by using stack') {
		while (@{$stack[-1]{nodes}} > 0) {
			my $item = shift @{$stack[-1]{nodes}};
			if (ref $item eq 'ARRAY') {

				# this value is the next level of the tree
				push @stack, {nodes => [@$item], results => []};
			}
			else {
				my $value;

				if (ref $item eq 'HASH') {
					$value = Bitcoin::Crypto::Script::Tree::Leaf->new(
						%{$item},
						depth => scalar @stack,
					);
				}
				elsif (blessed $item && $item->isa('Bitcoin::Crypto::Script::Tree::Leaf')) {
					$value = $item;
					$value->set_depth(scalar @stack);
				}

				Bitcoin::Crypto::Exception->raise(
					'unknown tree leaf: not a hash, or a Bitcoin::Crypto::Script::Tree::Leaf instance'
				) unless defined $value;

				push @{$leaves_ref}, $value;
				push @{$stack[-1]{results}}, $value;
			}
		}

		my @results = @{$stack[-1]{results}};
		if (@results == 2) {

			# sort result so that smaller hash values come first
			@results = reverse @results
				if $results[0]{hash} gt $results[1]{hash};

			my @all_ids;
			foreach my $key (keys @results) {
				my ($this_one, $other_one) = @results[$key, ($key + 1) % 2];

				my $is_leaf = blessed $this_one;
				my @ids = $is_leaf ? ($this_one->id) : @{$this_one->{ids}};
				push @all_ids, @ids;

				foreach my $id (@ids) {
					push @{$paths_ref->{$id}}, $other_one->{hash};
				}
			}

			$result = {
				ids => \@all_ids,
				hash => tagged_hash('TapBranch', join '', map { $_->{hash} } @results),
			};
		}
		elsif (@results == 1) {
			$result = $results[0];
		}
		else {
			Bitcoin::Crypto::Exception->raise(
				'invalid taproot script tree, not a binary tree'
			);
		}

		pop @stack;
		last unless @stack > 0;
		push @{$stack[-1]{results}}, $result;
	}

	return $result;
}

sub _build_tree_cache
{
	my ($self) = @_;

	my @leaves;
	my %paths;
	my $root = $self->_traverse(\%paths, \@leaves);

	return {
		leaves => \@leaves,
		paths => \%paths,
		root => $root,
	};
}

sub get_merkle_root
{
	my ($self) = @_;

	return $self->_tree_cache->{root}{hash};
}

signature_for get_leaf => (
	method => !!1,
	positional => [ByteStr],
);

sub get_leaf
{
	my ($self, $leaf_id) = @_;

	my $leaf = first { $_->{id} eq $leaf_id } @{$self->_tree_cache->{leaves}};
	Bitcoin::Crypto::Exception::ScriptTree->raise(
		"no such block with id=$leaf_id"
	) unless defined $leaf;

	return $leaf;
}

sub get_tapleaf_script
{
	my ($self, $leaf_id) = @_;

	carp 'get_tapleaf_script is deprecated - use get_leaf(...)->script instead';

	return $self->get_leaf($leaf_id)->script;
}

sub get_tapleaf_hash
{
	my ($self, $leaf_id) = @_;

	carp 'get_tapleaf_hash is deprecated - use get_leaf(...)->hash instead';

	return $self->get_leaf($leaf_id)->hash;
}

sub get_tapleaf_version
{
	my ($self, $leaf_id) = @_;

	carp 'get_tapleaf_version is deprecated - use get_leaf(...)->leaf_version instead';

	return $self->get_leaf($leaf_id)->leaf_version;
}

sub get_tree_paths
{
	my ($self) = @_;

	return $self->_tree_cache->{paths};
}

sub get_leaves
{
	my ($self) = @_;

	return $self->_tree_cache->{leaves};
}

signature_for from_path => (
	method => !!1,
	positional => [
		(InstanceOf ['Bitcoin::Crypto::Script::Tree::Leaf'])
			->plus_coercions(
				HashRef, q{ Bitcoin::Crypto::Script::Tree::Leaf->new($_) }
			),
		ArrayRef [ByteStr]
	],
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
	method => !!1,
	positional => [ByteStr, InstanceOf ['Bitcoin::Crypto::Key::Public']],
);

sub get_control_block
{
	my ($self, $leaf_id, $pubkey) = @_;
	my $cache = $self->_tree_cache;

	my $leaf_version = $self->get_leaf($leaf_id)->leaf_version;
	my $tapkey = $pubkey->get_taproot_output_key($cache->{root}{hash});
	my $parity = has_even_y($tapkey);

	return Bitcoin::Crypto::Transaction::ControlBlock->new(
		control_byte => $leaf_version | !$parity,
		public_key => $pubkey,
		script_blocks => $cache->{paths}{$leaf_id} // [],
	);
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Script::Tree - BIP341 Script trees

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_script_tree);
	use Bitcoin::Crypto qw(btc_tapscript);
	use Bitcoin::Crypto::Constants qw(:script);

	# create a script tree with three leaves, two of them prehashed. Mark the
	# third script with an id

	my $tree = btc_script_tree->new(
		tree => [
			{hash => [hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d']},
			[
				{
					id => 'leaf_1',
					leaf_version => TAPSCRIPT_LEAF_VERSION,
					script => btc_tapscript->new, # TODO: fill the script
				},
				{hash => [hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7']},
			]
		]
	);

	# get the tree merkle root hash
	my $hash = $tree->get_merkle_root;

=head1 DESCRIPTION

This module contains implementation of script trees described in
L<BIP341|https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>. These
trees are used by taproot and are necessary to build custom taproot scripts.

=head2 Tree leaves

Each leaf in the tree is represented with an instance of
L<Bitcoin::Crypto::Script::Tree::Leaf> class. During tree building, this Perl
structure is most often used, which is turned into an object automatically:

	{
		id => bytestring (optional),
		leaf_version => integer,
		script => Bitcoin::Crypto::Script instance (or its coercible),
	}

Optional C<id> is used to identify the leaf in the tree, which is used in
methods like L</get_control_block>. If it is not present, it is automatically
assigned as the hash of the leaf.

Currently, C<leaf_version> must be equal to
L<Bitcoin::Crypto::Constants/TAPSCRIPT_LEAF_VERSION>, since other versions are
reserved for future use. For this version, an instance of
L<Bitcoin::Crypto::Tapscript> should be used for C<script>.

Depth is set automatically for script leaves during tree cache building. If
depth is already set in a leaf, it gets overwritten.

If the leaf is prehashed or not known, it can be represented as this structure
instead:

	{
		hash => bytestring with prehashed leaf,
	}

Same logic can be applied if only the merkle root of the tree is known - simply
introduce a prehashed structure as the only element of the tree. This can be
useful in places where a script tree object is required for its root hash, but
you don't have the full tree - for example in PSBTs.

=head1 INTERFACE

=head2 Attributes

=head3 tree

I<Available in the constructor.>

Internal structure of the tree. This structure represents a binary tree and
must contain an array reference of array or hash references.

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
			leaf_version => TAPSCRIPT_LEAF_VERSION,
			script => [hex => '2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac']
		},
		[
			{
				id => 'interesting leaf',
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
			{
				leaf_version => TAPSCRIPT_LEAF_VERSION,
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
				leaf_version => TAPSCRIPT_LEAF_VERSION,
				script => [hex => '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac']
			},
			{hash => [hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7']},
		]
	]

The structure in C<tree> is considered immutable and will not be changed. All
data coercions will be done in separate structures, which can be cleared using
L</clear_tree_cache> to be updated if the source C<tree> has changed.

=head2 Methods

=head3 new

	$tree = $class->new(%args)

Standard Moo constructor - see L</Attributes>.

=head3 from_path

	$tree = $class->from_path($leaf, \@path)

This static method builds a new C<$tree> object from key path C<@path>. Key
path represents a script tree by a series of prehashed leaves. C<$leaf> is a
tree leaf as passed to L</tree> during tree construction. It is usually
deserialized from transaction data.

C<@path> must only contain bytestrings or their coercibles. Example C<@path>
could look like this:

	(
		[hex => 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7'],
		[hex => 'f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d'],
	)

=head3 get_merkle_root

	$hash = $tree->get_merkle_root()

Calculates a merkle root of the script tree. Returns a bytestring which is the
root hash of the tree.

=head3 get_leaf

	$leaf = $tree->get_leaf($id_or_hash)

Returns a tree leaf - instance of L<Bitcoin::Crypto::Script::Tree::Leaf>. If
the leaf does not exist, an exception is raised.

=head3 get_tapleaf_script

	$script = $tree->get_tapleaf_script($leaf_id)

Deprecated - use C<< $tree->get_leaf($leaf_id)->script >> instead.

Returns a tapleaf script of a leaf with given C<$leaf_id>. If such leaf does
not exist, an exception is thrown. Returns a script instance.

=head3 get_tapleaf_version

	$int = $tree->get_tapleaf_version($leaf_id)

Deprecated - use C<< $tree->get_leaf($leaf_id)->leaf_version >> instead.

Returns a tapleaf version of a leaf with given C<$leaf_id>. If such leaf does
not exist, an exception is thrown. Returns an integer.

=head3 get_tapleaf_hash

	$hash = $tree->get_tapleaf_hash($leaf_id)

Deprecated - use C<< $tree->get_leaf($leaf_id)->hash >> instead.

Calculates a tapleaf hash of a leaf with given C<$leaf_id>. If such leaf does
not exist, an exception is thrown. Returns a bytestring.

=head3 get_control_block

	$block = $tree->get_control_block($leaf_id, $pubkey)

Builds a taproot control block used in taproot witness data. C<$leaf_id> must
be a valid identifier of a leaf existing in the tree. C<$pubkey> is a public
key that associated with the address for key path spending. Returns an instance
of L<Bitcoin::Crypto::Transaction::ControlBlock>.

=head3 get_tree_paths

	$paths = $tree->get_tree_paths()

Returns a hash reference of paths for each of leaves in the tree which have an
id. Each path is an array reference - same as what L</from_path> takes as input.

=head3 get_leaves

	$leaves = $tree->get_leaves()

Returns an array reference of leaves in the hash - each leaf is an instance of
L<Bitcoin::Crypto::Script::Tree::Leaf>. The order of leaves in the array is
strictly determined by the order of leaves in the tree.

=head3 clear_tree_cache

	$tree->clear_tree_cache()

Clears the internal cache of the tree, forcing recalculation of merkle root and
all leaf hashes. Must be done after the internal structure of the tree
changed.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Tapscript>

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

