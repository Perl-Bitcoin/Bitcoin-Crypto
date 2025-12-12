package Bitcoin::Crypto::Secret;

use v5.14;
use warnings;

use Scalar::Util qw(refaddr);

use namespace::autoclean;

use overload
	q{""} => "as_string",
	fallback => 1;

my %secrets;

my $store_secret = sub {
	my ($obj, $secret) = @_;

	$secrets{$obj} = $secret;
	return;
};

my $retrieve_secret = sub {
	my ($obj) = @_;

	return undef unless exists $secrets{$obj};
	return $secrets{$obj};
};

my $delete_secret = sub {
	my ($obj) = @_;

	delete $secrets{$obj};
	return;
};

sub new
{
	my ($class, $secret) = @_;

	my $str = '[REDACTED]';
	my $self = bless \$str, $class;
	$store_secret->(refaddr $self, $secret);
	return $self;
}

sub unmask_to
{
	my ($self, $sub_ref) = @_;

	return $sub_ref->($retrieve_secret->(refaddr $self));
}

sub DESTROY
{
	my ($self) = @_;

	$delete_secret->(refaddr $self);
}

sub as_string
{
	return ${$_[0]};
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Secret - Storing secrets more safely

=head1 SYNOPSIS

	use Bitcoin::Crypto::Secret;

	my $secret = Bitcoin::Crypto::Secret->new('super secret password');
	say $secret; # prints "[REDACTED]"

	# format strings are ok
	my $secret_with_format = Bitcoin::Crypto::Secret->new([hex => '...']);

=head1 DESCRIPTION

This is a small class which improves the security of secrets stored in Perl
memory. It is an inside-out object which always stringifies to C<[REDACTED]>,
so that the secret will not get leaked accidentally, for example in dumps (like
Data::Dumper). Bitcoin::Crypto uses this class to store secrets internally,
B<regardless of whether you use it explicitly or not>. Plainstring secrets will
be turned into instances of Bitcoin::Crypto::Secret automatically.

Secrets returned from Bitcoin::Crypto functions are plain strings B<and not
instances of Bitcoin::Crypto::Secret>.

=head2 What is considered a secret?

Currently, following arguments to functions accept objects of
Bitcoin::Crypto::Secret:

=over

=item * C<$mnemonic> and C<$password> in L<Bitcoin::Crypto::Key::ExtPrivate/from_mnemonic>

=item * C<$seed> in L<Bitcoin::Crypto::Key::ExtPrivate/from_seed>

=item * C<$serialized> in L<Bitcoin::Crypto::Key::ExtPrivate/from_serialized>

=item * C<$wif> in L<Bitcoin::Crypto::Key::Private/from_wif>

=item * C<$serialized> in L<Bitcoin::Crypto::Key::Private/from_serialized>

=item * C<$wif> in L<Bitcoin::Crypto::Util/validate_wif>

=item * C<$entropy> in L<Bitcoin::Crypto::Util/mnemonic_from_entropy>

=item * C<$mnemonic> and C<$password> in L<Bitcoin::Crypto::Util/mnemonic_to_seed>

=back

=head2 Crypt::SecretBuffer awareness and partial compatibility

This class is partially compatible with L<Crypt::SecretBuffer>: the interface
of L</new> and L</unmask_to> is the same. In addition, it stringifies to the
same C<[REDACTED]> string. You can think of Bitcoin::Crypto::Secret as
"Crypt::SecretBuffer light", as it only tries to hide the secret from leaking
by accident, and not keep it away from perl's heap entirely. B<There is no way
to keep secrets away from perl's heap> when using Bitcoin::Crypto, as the
library manipulates the secrets with perl (non-XS) code.

That being said, if you want that little extra protection or other features of
L<Crypt::SecretBuffer>, Bitcoin::Crypto is aware of its existence and will
accept its objects in any place where a secret is expected. It will not try to
turn it into a Bitcoin::Crypto::Secret instance, but instead store it
internally as-is.

In order to use Crypt::SecretBuffer with Bitcoin::Crypto, it must be version
C<0.007> or greater, as this version introduced the C<unmask_to> method.

=head1 INTERFACE

=head2 Methods

=head3 new

	$secret = $class->new($data)

Creates a new secret instance holding C<$data>, which can be any defined value
(unlike L<Crypt::SecretBuffer/new>, which only accepts strings).

=head3 unmask_to

	$ret = $secret->unmask_to($sub)

Executes C<$sub> with a sole argument being a value of the secret. Returns
whatever C<$sub> returned. Fully compatible with
L<Crypt::SecretBuffer/unmask_to>.

=head3 as_string

	$str = $secret->as_string()

Always returns C<[REDACTED]>. This happens automatically on object
stringification. Unlike Crypt::SecretBuffer, there is no way to disable this
mark to make it stringify as the secret. If this is needed, this idiom can be
used:

	$data = $secret->unmask_to(sub { shift });

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Key::ExtPrivate>

=item L<Crypt::SecretBuffer>

=back

=cut

