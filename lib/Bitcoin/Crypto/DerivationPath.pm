package Bitcoin::Crypto::DerivationPath;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Type::Params -sigs;

use Bitcoin::Crypto::Types qw(Object Str Bool ArrayRef PositiveOrZeroInt);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Exception;

has param 'private' => (
	isa => Bool,
);

has param 'path' => (
	isa => ArrayRef [PositiveOrZeroInt],
);

with qw(Bitcoin::Crypto::Role::WithDerivationPath);

signature_for get_derivation_path => (
	method => Object,
	positional => [],
);

sub get_derivation_path
{
	my ($self) = @_;

	return $self;
}

signature_for from_string => (
	method => Str,
	positional => [Str],
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

			return undef if $part >= Bitcoin::Crypto::Constants::max_child_keys;

			$part += Bitcoin::Crypto::Constants::max_child_keys if $is_hardened;
			push @path, $part;
		}
	}

	return $class->new(
		private => $head eq 'm',
		path => \@path,
	);
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

B<Required>. A boolean - whether the path is private (started with lowercase
C<m>).

=head3 path

B<Required>. An array reference of unsigned integers - the derivation path.
Hardened keys are greater than or equal to 2^32
(C<Bitcoin::Crypto::Constants::max_child_keys>).

=head2 Methods

=head3 from_string

	my $path = Bitcoin::Crypto::DerivationPath->from_string($m_notation_string)

Constructs a new derivation path based on the string.

=head3 get_derivation_path

	my $self = $path->get_derivation_path()

A helper which returns self.

