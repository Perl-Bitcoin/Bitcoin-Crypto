package Bitcoin::Crypto::Transaction::Flags;

use v5.14;
use warnings;

use Mooish::Base -standard;

# BIP16
has param 'p2sh' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

has param 'signature_pushes_only' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

# BIP65
has param 'checklocktimeverify' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

# BIP66
has param 'der_signatures' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

# BIP112
has param 'checksequenceverify' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

# BIP141
has param 'segwit' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

# BIP147
has param 'nulldummy' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

# BIP341
has param 'taproot' => (
	coerce => Bool,
	default => 1,
	writer => 1,
);

# optional standardness rules below

# segwit only
has param 'minimalif' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

# segwit only
has param 'compressed_pubkeys' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'strict_encoding' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'low_s_signatures' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'minimaldata' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'nullfail' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'cleanstack' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'const_script' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'known_witness' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'illegal_upgradeable_nops' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

sub new_empty
{
	my ($self, %args) = @_;

	return $self->new(
		p2sh => !!0,
		signature_pushes_only => !!0,
		checklocktimeverify => !!0,
		der_signatures => !!0,
		checksequenceverify => !!0,
		segwit => !!0,
		nulldummy => !!0,
		taproot => !!0,
		%args,
	);
}

sub new_full
{
	my ($self, %args) = @_;

	return $self->new(
		minimalif => !!1,
		compressed_pubkeys => !!1,
		strict_encoding => !!1,
		low_s_signatures => !!1,
		minimaldata => !!1,
		nullfail => !!1,
		cleanstack => !!1,
		const_script => !!1,
		known_witness => !!1,
		illegal_upgradeable_nops => !!1,
		%args,
	);
}

sub strict_signatures
{
	my ($self) = @_;

	return $self->der_signatures
		|| $self->low_s_signatures
		|| $self->strict_encoding;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Transaction::Flags - Consensus flags

=head1 SYNOPSIS

	use Bitcoin::Crypto::Transaction::Flags;

	# full set of flags
	my $all_flags = Bitcoin::Crypto::Transaction::Flags->new;

	# disable some flags (those not passed are active)
	my $some_flags = Bitcoin::Crypto::Transaction::Flags->new(
		strict_signatures => !!0,
	);

	# use flags in transaction verification
	$transaction->verify(flags => $some_flags);

=head1 DESCRIPTION

This is a class that represents a set of consensus rules used in transaction
verification and associated systems. Each attribute of this class represents a
single rule.

By default, all implemented consensus rules are active. As Bitcoin
and this module progress, more rules may be added all enabled by default on
arrival. Since Bitcoin is extended through softforks (implemented in a
backward-compatible manner), this should rarely pose a problem with
Bitcoin::Crypto code. If you want to be extra sure, see L</new_empty>.

=head1 INTERFACE

=head2 Attributes

=head3 p2sh

I<Available in the constructor>.

Whether P2SH verification defined in
L<BIP16|https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki> should
be used.

I<writer:> C<set_p2sh>

=head3 strict_signatures

I<Available in the constructor>.

Whether strict DER signature verification defined in
L<BIP66|https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki> should
be used.

I<writer:> C<set_strict_signatures>

=head3 checklocktimeverify

I<Available in the constructor>.

Whether C<OP_CHECKLOCKTIMEVERIFY> opcode defined in
L<BIP65|https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki> should
be used.

I<writer:> C<set_checklocktimeverify>

=head3 checksequenceverify

I<Available in the constructor>.

Whether C<OP_CHECKSEQUENCEVERIFY> opcode defined in
L<BIP112|https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki> should
be used.

I<writer:> C<set_checksequenceverify>

=head3 nulldummy

I<Available in the constructor>.

Whether C<OP_CHECKMULTISIG> nulldummy verification defined in
L<BIP147|https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki> should
be used.

I<writer:> C<set_nulldummy>

=head3 segwit

I<Available in the constructor>.

Whether segwit-specific verification defined in
L<BIP141|https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki> should
be used.

I<writer:> C<set_segwit>

=head3 taproot

I<Available in the constructor>.

Whether taproot-specific verification defined in
L<BIP341|https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki> should
be used.

I<writer:> C<set_taproot>

=head2 Methods

=head3 new

	$object = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

Returns a class instance.

=head3 new_empty

	$object = $class->new_empty(%args)

Same as L</new>, but assumes all flags unspecified in C<%args> are disabled.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

