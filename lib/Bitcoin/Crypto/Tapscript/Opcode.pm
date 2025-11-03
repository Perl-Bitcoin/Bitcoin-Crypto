package Bitcoin::Crypto::Tapscript::Opcode;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;

use List::Util qw(none);
use Bitcoin::Crypto qw(btc_pub);
use Bitcoin::Crypto::Util qw(lift_x);
use Bitcoin::Crypto::Script::Opcode;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

extends 'Bitcoin::Crypto::Script::Opcode';

# TODO: BIP 342 sigopt budget

sub _OP_CHECKSIG
{
	return sub {
		my ($runner) = @_;

		my $stack = $runner->stack;
		$runner->_stack_error unless @$stack >= 2;

		my $raw_pubkey = pop @$stack;
		my $sig = pop @$stack;

		my $pubkey;
		my $hashtype;

		# rules according to https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#rules-for-signature-opcodes
		if (length $raw_pubkey == 32) {
			$pubkey = btc_pub->from_serialized(lift_x $raw_pubkey);
			$pubkey->set_taproot_output(!!1);
		}
		elsif (length $raw_pubkey == 0) {
			$runner->_invalid_script('bad pubkey');
		}
		else {
			# unknown key type
			push @$stack, $runner->from_bool(!!1);
			return;
		}

		if (length $sig == 0) {

			# empty signature
			push @$stack, $runner->from_bool(!!0);
			return;
		}
		else {
			$hashtype = length $sig == 65 ? unpack('C', substr $sig, -1, 1, '') : undef;
			state $allowed_sighash = [
				Bitcoin::Crypto::Constants::sighash_all,
				Bitcoin::Crypto::Constants::sighash_all | Bitcoin::Crypto::Constants::sighash_anyonecanpay,
				Bitcoin::Crypto::Constants::sighash_single,
				Bitcoin::Crypto::Constants::sighash_single | Bitcoin::Crypto::Constants::sighash_anyonecanpay,
				Bitcoin::Crypto::Constants::sighash_none,
				Bitcoin::Crypto::Constants::sighash_none | Bitcoin::Crypto::Constants::sighash_anyonecanpay,
			];

			$runner->_invalid_script('bad sighash')
				if defined $hashtype && none { $hashtype == $_ } @$allowed_sighash;
		}

		my $ext_flag = $runner->transaction->taproot_ext_flag;
		my $ext;

		# leaf for this script must be defined with id 0 to get a proper hash
		if ($ext_flag == 1) {
			my $codesep_pos = $runner->_codeseparator || 0xffffffff;
			my $leaf_hash = $runner->transaction->taproot_script_tree->get_tapleaf_hash(0);

			# https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension
			$ext = $leaf_hash . "\x00" . pack 'V', $codesep_pos;
		}

		my $preimage = $runner->transaction->get_digest($runner->subscript, $hashtype, $ext);
		my $result = $pubkey->verify_message($preimage, $sig);

		$runner->_invalid_script('signature verification failed') unless $result;
		push @$stack, $runner->from_bool($result);
	};
}

sub _OP_CHECKMULTISIG
{
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

	my %opcodes = (
		%parent_opcodes,
		OP_CHECKSIG => {
			code => 0xac,
			needs_transaction => !!1,
			runner => __PACKAGE__->_OP_CHECKSIG,
		},
		OP_CHECKMULTISIG => {
			code => 0xae,
			needs_transaction => !!1,
			runner => __PACKAGE__->_OP_CHECKMULTISIG,
		},
		OP_CHECKSIGADD => {
			code => 0xba,
			needs_transaction => !!1,
			runner => __PACKAGE__->_OP_CHECKSIGADD,
		},
	);

	my %opcodes_by_code = map { $opcodes{$_}{code} => $_ } keys %opcodes;

	# https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#specification
	for my $succ (80, 98, 126 .. 129, 131 .. 134, 137, 138, 141, 142, 149 .. 153, 187 .. 254) {
		delete $opcodes{$opcodes_by_code{$succ}}
			if exists $opcodes_by_code{$succ};

		$opcodes{"OP_SUCCESS$succ"} = {
			code => $succ,
			on_compilation => sub {
				my ($runner, $opcode) = @_;

				Bitcoin::Crypto::Exception::ScriptSuccess->raise('OP_SUCCESS encountered');
			},
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

