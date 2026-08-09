package Bitcoin::Crypto::Tapscript::Opcode;

use v5.14;
use warnings;

use Mooish::Base -standard;

use List::Util qw(none);
use Bitcoin::Crypto::Util::Internal qw(lift_x get_taproot_ext);
use Bitcoin::Crypto::Helpers qw(ecc die_no_trace);
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Constants qw(:sighash);

extends 'Bitcoin::Crypto::Script::Opcode';

sub _compile_OP_SUCCESS
{
	my ($class) = @_;

	return sub {
		my ($compiler) = @_;

		$compiler->_unconditionally_valid_script('OP_SUCCESS encountered');
	};
}

sub _OP_CHECKSIG
{
	my ($class) = @_;

	return sub {
		my $runner = shift;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 2;

		my $raw_pubkey = pop @$stack;
		my $sig = pop @$stack;

		my $known_pubkey_type;
		my $hashtype;

		# rules according to https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#rules-for-signature-opcodes
		if (length $raw_pubkey == 32) {
			$known_pubkey_type = !!1;
		}
		elsif (length $raw_pubkey == 0) {
			$runner->_invalid_script('bad pubkey');
		}
		else {
			$known_pubkey_type = !!0;
		}

		if (length $sig == 0) {

			# empty signature
			push @$stack, $runner->from_bool(!!0);
			return;
		}
		else {
			($sig, $hashtype) = unpack 'a64C', $sig
				if length $sig == 65;

			state $allowed_sighash = {
				map { $_ => !!1 } (
					SIGHASH_ALL,
					SIGHASH_ALL | SIGHASH_ANYONECANPAY,
					SIGHASH_SINGLE,
					SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
					SIGHASH_NONE,
					SIGHASH_NONE | SIGHASH_ANYONECANPAY,
				)
			};

			$runner->_invalid_script('bad sighash')
				if defined $hashtype && !$allowed_sighash->{$hashtype};
		}

		my $tx = $runner->transaction;

		$runner->_invalid_script('sigop budget exceeded')
			unless $tx->reduce_sigop_budget;

		my $ext_flag = $tx->taproot_ext_flag;
		my $ext;

		if ($ext_flag == 1) {

			die_no_trace 'no script_tree in script transaction object'
				unless $tx->has_script_tree;

			$ext = get_taproot_ext(
				$ext_flag,
				script_tree => $tx->script_tree,
				leaf_id => $tx->leaf_id,
				codesep_pos => $runner->codeseparator,
			);
		}

		if (!$known_pubkey_type) {
			push @$stack, $runner->from_bool(!!1);
			return;
		}

		my $preimage = $tx->get_digest(
			sighash => $hashtype,
			taproot_ext => $ext
		);

		# TODO: this uses ecc directly and skips creating a new public key
		# with lift_x - this saves time, but maybe an abstraction for that
		# should be made as Key::Schnorr (which would use SignVerify)?
		my $result = ecc->verify_digest_schnorr($raw_pubkey, $sig, $preimage->hash);

		$runner->_invalid_script('signature verification failed') unless $result;
		push @$stack, $runner->from_bool($result);
	};
}

sub _OP_CHECKMULTISIG
{
	my ($class) = @_;

	return sub {
		my $runner = shift;

		$runner->_invalid_script;
	};
}

sub _OP_CHECKSIGADD
{
	my ($class) = @_;

	my $checksig = $class->_OP_CHECKSIG;

	return sub {
		my $runner = shift;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 3;
		my $n = $runner->to_int(splice @$stack, -2, 1);

		$checksig->($runner);
		push @$stack, $runner->from_int($n + $runner->to_int(pop @$stack));
	};
}

sub _build_opcodes
{
	my ($class) = @_;
	my %parent_opcodes = $class->SUPER::_build_opcodes;

	# NOTE: multisig no longer is a sigop and no longer requires transaction

	my %opcodes = (
		%parent_opcodes,
		OP_CHECKSIG => {
			code => 0xac,
			needs_transaction => !!1,
			sigop => !!1,
			runner => $class->_OP_CHECKSIG,
		},
		OP_CHECKMULTISIG => {
			code => 0xae,
			needs_transaction => !!1,
			runner => $class->_OP_CHECKMULTISIG,
		},
		OP_CHECKMULTISIG => {
			code => 0xae,
			runner => $class->_OP_CHECKMULTISIG,
		},
		OP_CHECKMULTISIGVERIFY => {
			code => 0xae,
			runner => $class->_OP_CHECKMULTISIGVERIFY,
		},
		OP_CHECKSIGADD => {
			code => 0xba,
			needs_transaction => !!1,
			sigop => !!1,
			runner => $class->_OP_CHECKSIGADD,
		},
	);

	my %opcodes_by_code = map { $opcodes{$_}{code} => $_ } keys %opcodes;

	# https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#specification
	for my $succ (80, 98, 126 .. 129, 131 .. 134, 137, 138, 141, 142, 149 .. 153, 187 .. 254) {
		delete $opcodes{$opcodes_by_code{$succ}}
			if exists $opcodes_by_code{$succ};

		$opcodes{"OP_SUCCESS$succ"} = {
			code => $succ,
			on_compilation => $class->_compile_OP_SUCCESS,
		};
	}

	return %opcodes;
}

1;

__END__

=head1 NAME

Bitcoin::Crypto::Tapscript::Opcode - Bitcoin opcodes specific to tapscript

=head1 SYNOPSIS

	use Bitcoin::Crypto::Tapscript::Opcode;

	# same usage as Bitcoin::Crypto::Script::Opcode

=head1 DESCRIPTION

This module is functionally equal to L<Bitcoin::Crypto::Script::Opcode>, but it
contains tapscript-specific changes to Bitcoin opcodes defined in
L<BIP-342|https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki>.

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Tapscript>

=item L<Bitcoin::Crypto::Script::Opcode>

=back

=cut

