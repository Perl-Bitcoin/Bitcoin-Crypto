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
has param 'null_dummy' => (
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

has param 'signature_pushes_only' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

# segwit only
has param 'minimal_if' => (
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

has param 'minimal_data' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'null_fail' => (
	coerce => Bool,
	default => 0,
	writer => 1,
);

has param 'clean_stack' => (
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
		checklocktimeverify => !!0,
		der_signatures => !!0,
		checksequenceverify => !!0,
		segwit => !!0,
		null_dummy => !!0,
		taproot => !!0,
		%args,
	);
}

sub new_full
{
	my ($self, %args) = @_;

	return $self->new(
		signature_pushes_only => !!1,
		minimal_if => !!1,
		compressed_pubkeys => !!1,
		strict_encoding => !!1,
		low_s_signatures => !!1,
		minimal_data => !!1,
		null_fail => !!1,
		clean_stack => !!1,
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

	# full set of flags (standardness rules)
	my $all_flags = Bitcoin::Crypto::Transaction::Flags->new_full;

	# default set of flags (consensus rules)
	my $consensus_flags = Bitcoin::Crypto::Transaction::Flags->new;

	# disable some flags
	my $some_flags = Bitcoin::Crypto::Transaction::Flags->new(
		der_signatures => !!0,
	);

	# use flags in transaction verification
	$transaction->verify(flags => $some_flags);

=head1 DESCRIPTION

This is a class that represents a set of consensus rules used in transaction
verification and associated systems. Each attribute of this class represents a
single rule.

By default, all implemented consensus rules are active, and all implemented
standardness rules are inactive when calling L</new>. As Bitcoin and this
module progress, more rules may be added all enabled by default on arrival.
Since Bitcoin is extended through softforks (implemented in a
backward-compatible manner), this should rarely pose a problem with
Bitcoin::Crypto code. If you want to be extra sure, see L</new_empty>.

To verify a transaction which will go through mempool, L</new_full> should be
used, as it verifies all rules which must be satisfied by a transaction (both
consensus and standardness).

=head1 INTERFACE

All the following flags are attributes available in the constructor of the
object. They have writer methods named C<set_X>.

=head2 Consensus flags

All consensus flags are active by default.

=head3 p2sh

Whether P2SH verification defined in
L<BIP16|https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki> should
be used.

=head3 der_signatures

Whether strict DER signature verification defined in
L<BIP66|https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki> should
be used.

=head3 checklocktimeverify

Whether C<OP_CHECKLOCKTIMEVERIFY> opcode defined in
L<BIP65|https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki> should
be used.

=head3 checksequenceverify

Whether C<OP_CHECKSEQUENCEVERIFY> opcode defined in
L<BIP112|https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki> should
be used.

=head3 null_dummy

Whether C<OP_CHECKMULTISIG> null dummy verification defined in
L<BIP147|https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki> should
be used.

=head3 segwit

Whether segwit-specific verification defined in
L<BIP141|https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki> should
be used.

=head3 taproot

Whether taproot-specific verification defined in
L<BIP341|https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki> should
be used.

=head2 Standardness flags

All standardness flags are inactive by default.

=head3 signature_pushes_only

Disallows non-push opcodes in signature scripts of inputs for legacy non-P2SH
transactions. Automatically active for P2SH.

=head3 minimal_if

Whether the argument to C<OP_IF> must be minimal (C<OP_1> or C<OP_0>). Only
applicable to Segregated Witness scripts.

=head3 compressed_pubkeys

Whether public keys used is signature-checking scripts must be compressed. Only
applicable to Segregated Witness scripts.

=head3 strict_encoding

Disallows non-strictly encoded DER signatures and public keys.

=head3 low_s_signatures

Disallows signatures encoded with low S.

=head3 minimal_data

When active, data pushed by push opcodes must be minimally encoded.

=head3 null_fail

Causes non-taproot signature-checking opcodes to stop script execution on
failure, unless the signature is empty.

=head3 clean_stack

Requires script stack to have exactly one element at the end of execution to
consider the execution successful.

=head3 const_script

Causes the script to fail if C<OP_CODESEPARATOR> or a signature is encoded in a
pre-SegWit script.

=head3 known_witness

Causes the transaction verification to fail if unknown version of Segregated
Witness program is encountered.

=head3 illegal_upgradeable_nops

Disallows the use of C<OP_NOPX> opcodes (but not C<OP_NOP>).

=head2 Methods

=head3 new

	$object = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Consensus flags> and L</Standardness flags>.

Returns a class instance.

=head3 new_empty

	$object = $class->new_empty(%args)

Same as L</new>, but assumes all flags unspecified in C<%args> are disabled.

=head3 new_full

	$object = $class->new_full(%args)

Same as L</new>, but assumes all flags unspecified in C<%args> are enabled.

=head3 strict_signatures

	$bool = $object->strict_signatures()

Return true if any one of L</strict_encoding>, L</der_signatures> or
L</low_s_signatures> are enabled. Having either one of these flags in effect is
the same as having L</der_signatures> enabled.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Transaction>

=back

=cut

