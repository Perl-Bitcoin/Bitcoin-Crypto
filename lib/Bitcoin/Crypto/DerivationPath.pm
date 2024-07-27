package Bitcoin::Crypto::DerivationPath;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;

has param 'private' => (
	isa => Bool,
);

has param 'path' => (
	isa => ArrayRef [PositiveOrZeroInt],
);

with qw(Bitcoin::Crypto::Role::WithDerivationPath);

use overload
	q{""} => sub { shift->as_string },
	fallback => 1;

signature_for get_derivation_path => (
	method => Object,
	positional => [],
);

sub get_derivation_path
{
	my ($self) = @_;

	return $self;
}

signature_for get_path_hardened => (
	method => Object,
	positional => [],
);

sub get_path_hardened
{
	my ($self) = @_;

	my $path = $self->path;
	return [
		map {
			my $hardened = $_ >= Bitcoin::Crypto::Constants::max_child_keys;
			my $value = $_ - ($hardened * Bitcoin::Crypto::Constants::max_child_keys);
			[$value, $hardened];
		} @$path
	];
}

signature_for get_path_hardened => (
	method => Object,
	positional => [],
);

sub from_string
{
	my ($class, $string) = @_;

	Bitcoin::Crypto::Exception->raise(
		"Invalid derivation path string: not a valid 'm' notation"
	) unless $string =~ m{\A ([mM]) ((?: / \d+ '?)*) \z}x;

	my ($head, $rest) = ($1, $2);
	my @path;

	if (defined $rest && length $rest > 0) {

		# remove leading slash (after $head)
		substr $rest, 0, 1, '';

		for my $part (split '/', $rest) {
			my $is_hardened = $part =~ tr/'//d;

			Bitcoin::Crypto::Exception->raise(
				"Derivation path part too large: $part"
			) if $part >= Bitcoin::Crypto::Constants::max_child_keys;

			$part += Bitcoin::Crypto::Constants::max_child_keys if $is_hardened;
			push @path, $part;
		}
	}

	return $class->new(
		private => $head eq 'm',
		path => \@path,
	);
}

signature_for as_string => (
	method => Object,
	positional => [],
);

sub as_string
{
	my ($self) = @_;

	my $string = $self->private ? 'm' : 'M';

	foreach my $item (@{$self->get_path_hardened}) {
		$string .= '/' . $item->[0] . ($item->[1] ? q{'} : '');
	}

	return $string;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::DerivationPath - Path for BIP32 key derivation

=head1 SYNOPSIS

	use Bitcoin::Crypto::DerivationPath;

	my $derivation_path = Bitcoin::Crypto::DerivationPath->from_string("m/1/2'/3");

	say $derivation_path->private;
	say $_ for @{$derivation_path->path};

=head1 DESCRIPTION

This is a helper object which represents the key derivation path parsed from
the C<m> notation. It is returned by L<Bitcoin::Crypto::Util/get_path_info>.

=head1 INTERFACE

=head2 Attributes

=head3 private

B<Required in the constructor>. A boolean - whether the path is private (started with lowercase
C<m>).

=head3 path

B<Required in the constructor>. An array reference of unsigned integers - the derivation path.
Hardened keys are greater than or equal to C<2^31>
(C<Bitcoin::Crypto::Constants::max_child_keys>).

=head2 Methods

=head3 from_string

	$path = Bitcoin::Crypto::DerivationPath->from_string($m_notation_string)

Constructs a new derivation path based on the string.

=head3 as_string

	$m_notation_string = $object->as_string;

Does the reverse of L</from_string>.

=head3 get_derivation_path

	$path = $path->get_derivation_path()

A helper which returns self.

=head3 get_path_hardened

	$hardened = $path->get_path_hardened()

Returns an array reference. Each item in the array is an array reference with
two values, where the first one is the path key and the second one is a boolean
indicating whether that key is hardened. The first value will always be within
the range C<0 .. 2^31 - 1> (unlike L</path>, which has keys larger than that
for hardened keys).

