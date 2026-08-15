package Bitcoin::Crypto::Script::Tree::Leaf;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Util::Internal qw(tagged_hash pack_compactsize);

has option 'depth' => (
	isa => PositiveInt,
	writer => 1,
);

has option 'leaf_version' => (
	isa => IntMaxBits [8],
);

has option 'script' => (
	coerce => BitcoinScript,
);

has param 'id' => (
	coerce => ByteStr,
	lazy => sub { shift->hash },
);

has param 'hash' => (
	coerce => ByteStr,
	lazy => 1,
);

sub BUILD
{
	my ($self) = @_;

	$self->hash;    # forces integrity check and fills ->{hash} slot
}

sub _build_hash
{
	my ($self) = @_;

	Bitcoin::Crypto::Exception::ScriptTree->raise(
		'calculating tree leaf hash requires a leaf_version plus a script'
	) unless $self->has_leaf_version && $self->has_script;

	my $script = $self->script->to_serialized;
	my $script_len = pack_compactsize(length $script);

	return tagged_hash('TapLeaf', join '', pack('C', $self->leaf_version), $script_len, $script);
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Script::Tree::Leaf - A leaf in a script tree

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_script);
	use Bitcoin::Crypto::Script::Tree::Leaf;
	use Bitcoin::Crypto::Constants qw(:script);

	my $leaf = Bitcoin::Crypto::Script::Tree::Leaf->new(
		leaf_version => TAPSCRIPT_LEAF_VERSION,
		script => [address => $address_string],
	);

	# calculate and print the hash
	say $leaf->hash;

=head1 DESCRIPTION

This class represents a leaf in a script tree. It is a simple structure to hold
leaf data, with automatic calculation of leaf hashes.

See L<Bitcoin::Crypto::Script::Tree> for tree usage details.

=head1 INTERFACE

=head2 Attributes

=head3 depth

I<Available in the constructor.>

Optional integer tree depth for this leaf. Minimum depth is 1. If a leaf was
created by a tree (during tree cache building), its depth is always present.

I<predicate:> C<has_depth>

I<writer:> C<set_depth>

=head3 id

I<Available in the constructor.>

Optional bytestring identifier for this leaf. If it was not passed, it is
filled with the value of L</hash>.

=head3 leaf_version

I<Available in the constructor.>

Optional integer leaf version. Most often the value
L<Bitcoin::Crypto::Constants/TAPSCRIPT_LEAF_VERSION> will be used.

I<predicate:> C<has_leaf_version>

=head3 script

I<Available in the constructor.>

Optional script instance.

I<predicate:> C<has_script>

=head3 hash

I<Available in the constructor.>

Optional bytestring leaf hash. If it was not passed, it will be calculated from
L</leaf_version> and L</script>.

Note that if you specify both hash and script / leaf_version, the correctness of
the hash will not be checked.

=head2 Methods

=head3 new

	$leaf_object = $class->new()

Standard Moo constructor - see L</Attributes>.

Objects of this class must be constructed with either L</leaf_version> and
L</script>, or a L</hash>. This will be checked upon object construction.

