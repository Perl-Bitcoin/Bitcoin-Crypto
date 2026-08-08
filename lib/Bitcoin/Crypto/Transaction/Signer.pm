package Bitcoin::Crypto::Transaction::Signer;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common qw(signature_for);    # frees up 'signature' for our field
use Carp qw(croak);

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Script::Runner;
use Bitcoin::Crypto::Util::Internal qw(to_format);
use Bitcoin::Crypto::Helpers qw(die_no_trace);

has param 'transaction' => (
	isa => InstanceOf ['Bitcoin::Crypto::Transaction'],
);

has param 'signing_index' => (
	isa => PositiveOrZeroInt,
);

has param 'script' => (
	coerce => BitcoinScript,
);

has field 'signature' => (
	isa => ArrayRef,
	default => sub { [] },
);

has field '_runner' => (
	isa => InstanceOf ['Bitcoin::Crypto::Script::Runner'],
	lazy => 1,
);

sub _build_runner
{
	my ($self) = @_;

	# clone a transaction and input. Some subclasses may want to modify it
	my $ind = $self->signing_index;
	my $temp_tx = $self->transaction->clone;
	$temp_tx->inputs->[$ind] = $temp_tx->inputs->[$ind]->clone;

	my $runner = Bitcoin::Crypto::Script::Runner->new(
		transaction => $temp_tx,
	);

	$runner->transaction->set_input_index($ind);
	$runner->start($self->script);
	return $runner;
}

sub _find_next_sigop
{
	my ($self, $error) = @_;
	$error //= !!1;

	my $runner = $self->_runner;
	my $ops = $runner->operations;
	Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			while ('finding sigop') {
				my $pos = $runner->pos;

				if ($pos > $#$ops) {
					die_no_trace 'could not find a sigop' if $error;
					last;
				}

				last if $ops->[$pos][0]->sigop;
				$runner->step;
			}
		},
		'finding next sigop failed'
	);

	return $runner;
}

sub _step_over_sigop
{
	my ($self) = @_;
	Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			$self->_runner->step;
		},
		'stepping over sigop failed'
	);
}

sub _multisigop
{
	my ($self) = @_;

	my $runner = $self->_runner;
	my $op = $runner->operations->[$runner->pos];

	return $op && $op->[0]->name =~ /OP_CHECKMULTISIG/;
}

sub _get_signature
{
	die 'unimplemented';
}

sub _initialize
{
	die 'unimplemented';
}

sub _finalize
{
	die 'unimplemented';
}

sub BUILD
{
	my ($self) = @_;

	$self->_initialize;
}

sub new_impl
{
	my ($class, $transaction, $args) = @_;

	$args->{transaction} = $transaction;
	Bitcoin::Crypto::Exception::Sign->raise(
		'signing_index is required'
	) unless defined $args->{signing_index};

	my $input = $transaction->inputs->[$args->{signing_index}];

	Bitcoin::Crypto::Exception::Sign->raise(
		'no such input'
	) unless defined $input;

	my $type = $input->utxo->output->locking_script->type // '';

	state $known_types = {map { $_ => 1 } qw(P2PKH P2SH P2WPKH P2WSH P2TR)};

	my $impl_class;
	if ($type eq 'P2SH' && $args->{compat}) {
		$impl_class = $args->{script} ? 'CompatP2WSH' : 'CompatP2WPKH';
	}
	elsif ($known_types->{$type}) {
		$impl_class = $type;
	}
	else {
		$impl_class = 'CustomLegacy';
	}

	$impl_class = "Bitcoin::Crypto::Transaction::Signer::$impl_class";

	eval "require $impl_class; 1" or die $@;
	return $impl_class->new($args);
}

signature_for add_bytes => (
	method => !!1,
	positional => [ByteStr],
);

sub add_bytes
{
	my ($self, $bytes) = @_;

	unshift @{$self->_runner->stack}, $bytes;
	push @{$self->signature}, $bytes;

	return $self;
}

signature_for add_number => (
	method => !!1,
	positional => [Int | Str | InstanceOf ['Math::BigInt']],
);

sub add_number
{
	my ($self, $number) = @_;

	return $self->add_bytes(Bitcoin::Crypto::Script::Runner->from_int($number));
}

signature_for add_signature => (
	method => !!1,
	head => [ByteStr | InstanceOf ['Bitcoin::Crypto::Key::Private']],
	named => [
		sighash => Maybe [PositiveOrZeroInt],
		{default => undef},
	],
	bless => !!0,
);

sub add_signature
{
	my ($self, $privkey_or_signature, $args) = @_;
	my $signature;
	my $runner = $self->_find_next_sigop;

	if (!ref $privkey_or_signature) {
		$signature = $privkey_or_signature;
	}
	else {
		$signature = $self->_get_signature($privkey_or_signature, $args);
	}

	$self->add_bytes($signature);
	$self->_step_over_sigop
		unless $self->_multisigop;

	return $self;
}

sub finalize_multisignature
{
	my ($self) = @_;

	Bitcoin::Crypto::Exception::Sign->raise(
		'not on multisignature opcode'
	) unless $self->_multisigop;

	# add mandatory null dummy element
	$self->add_bytes('');
	$self->_step_over_sigop;

	return $self;
}

sub finalize
{
	my ($self) = @_;

	$self->_finalize;

	# no $self returned anymore - this object is done
	return;
}

signature_for dump => (
	method => !!1,
	positional => [Bool, {default => !!1}],
);

sub dump
{
	my ($self, $find_sigop) = @_;

	my $runner = $self->_runner;
	$self->_find_next_sigop(!!0)
		if $find_sigop;

	my $pos = $runner->pos;
	my $ops = $runner->operations;

	my @result;
	push @result, "at position $pos (marked by **)";

	my @ops_dump;
	for my $this_pos ($pos - 2 .. $pos + 2) {
		my $op = $ops->[$this_pos];
		push @ops_dump, '**'
			if $this_pos == $pos;
		next unless $op;

		push @ops_dump, $op->[0]->name;
	}
	push @result, join ' ', @ops_dump;

	push @result, 'stack contents:';
	foreach my $item (@{$runner->stack}) {
		push @result, '> ' . to_format [hex => $item];
	}

	return join "\n", @result;
}

signature_for dump_abort => (
	method => !!1,
	positional => [Bool, {default => !!1}],
);

sub dump_abort
{
	my ($self, $find_sigop) = @_;

	say $self->dump($find_sigop);
	croak 'signing aborted';
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Transaction::Signer - Construct a signature for any transaction

=head1 SYNOPSIS

	# sign a multisignature transaction
	$tx->sign(signing_index => 0, script => $p2ms_script, %more_args)
		->add_signature($priv, SIGHASH_ALL)
		->add_signature('bytestring signature')
		->finalize_multisignature
		->finalize;

=head1 DESCRIPTION

This class implements a signer for transactions of any complexity. It is best
used for custom transactions which cannot be signed by calling
L<Bitcoin::Crypto::Key::Private/sign_transaction>.

It works by running the script in the background, progressing it with each
added signature. Executing the script allows finding the correct
signature-checking opcodes to sign by simulating how the script will behave
when the transaction is verified. No changes to the underlying transaction are
applied until the signature is finalized.

Note that since transactions use stack as a data structure, the order of
generated signature will be reversed, which may be surprising when inspecting
the transaction. Method calls must be done in order of opcode execution.

=head1 INTERFACE

Attributes vary depending on signing output type.

=head2 Common attributes

These attributes are common for all output types.

=head3 transaction

Mandatory transaction object. No need to include it when calling
L<Bitcoin::Crypto::Transaction/sign>, because it will be included
automatically.

=head3 signing_index

The index of input being signed. Required.

=head3 script

The script being signed. It is required for script hash output types (C<P2SH>
and C<P2WSH>). Otherwise it will be taken from output locking script. In
taproot script spends, it will be taken from L</script_tree> and L</leaf_id>.

=head3 signature

Not available in the constructor. This is an array reference with the current
bytestrings which will be used as a signature. Can be used to manually retrieve
generated signatures or to debug step by step.

Note that the signature may contain more than just what you add to it with
method calls. For example, for segwit's P2WPKH, it will contain a serialized
public key before the signature.

=head2 Taproot attributes

These attributes are only used for taproot outputs.

=head3 script_tree

L<Bitcoin::Crypto::Script::Tree> instance with a script tree used when creating
the taproot output. Must be passed for script spends or key spends with enabled
script path.

=head3 leaf_id

Numeric identifier which marks the leaf in L</script_tree>. Must be passed for
script spends.

=head3 public_key

A taproot internal key which was used for creating this output. Must be passed
for script spends.

=head3 taproot_ext_flag

A taproot extension flag for script spends. By default, a value C<1> (for
tapscript) is used.

=head2 Methods

=head3 new

	$signer = $class->new(%args)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Common attributes> and L</Taproot attributes>.
Usually, there is no need to call this method directly, as it will be called by
L<Bitcoin::Crypto::Transaction/sign> on the correct Signer subclass.

Returns class instance.

=head3 add_bytes

	$signer = $signer->add_bytes($bytestr)

Adds raw bytes from C<$bytestr> into the signature. Note that this should not
be used to add signatures - use L</add_signature> with bytes instead.

Returns the instance, for chaining.

=head3 add_number

	$signer = $signer->add_number($num)

Adds a script number C<$num> into the signature.

Returns the instance, for chaining.

=head3 add_signature

	$signer = $signer->add_signature($bytestr, %args)
	$signer = $signer->add_signature($privkey, %args)

Adds a signature to the transaction. If C<$privkey> is passed
(L<Bitcoin::Crypto::Key::Private>), then it will be used to sign the next
signature-checking opcode in the script. If C<$bytestr> is passed, then it will
be used as-is, but unlike L</add_bytes>, next call to C<add_signature> will
correctly target next opcode.

If the next signature-checking opcode is a multisig, then it will not step over
it after the call, but wait for a mandatory L</finalize_multisignature> call.

C<%args> can be any of:

=over

=item * C<sighash>

The sighash which should be used for the signature. By default L<Bitcoin::Crypto::Constants/SIGHASH_ALL>
is used for pre-taproot outputs and L<Bitcoin::Crypto::Constants/SIGHASH_DEFAULT> for taproot
outputs.

=back

Returns the instance, for chaining.

=head3 finalize_multisignature

	$signer = $signer->finalize_multisignature()

Used to finalize signing of multisig opcodes. It is mandatory to call it when
signing a multisig transaction.

Returns the instance, for chaining.

=head3 finalize

	$signer->finalize()

Finalizes the signing process, applying changes on the transaction object.
After this call, the C<$signer> object is done and should be discarded as soon
as possible.

Returns nothing, as the signing process is done.

