package Bitcoin::Crypto::Role::PSBT::Finalizer;

use v5.14;
use warnings;

use Mooish::Base -standard, -role;
use Bitcoin::Crypto qw(btc_script);

requires qw(
	version
	get_all_fields
	get_transaction
);

sub _should_finalize_P2PKH
{
	my ($self, $input, $input_index) = @_;

	# are there any partial signatures?
	my @partials = $self->get_all_fields('PSBT_IN_PARTIAL_SIG', $input_index);
	return () unless @partials;

	my $pkh = $input->utxo->output->locking_script->get_raw_address;
	foreach my $sig (@partials) {
		return ({type => 'signature', sigs => [$sig->value, $sig->key->to_serialized]})
			if $sig->key->get_hash eq $pkh;
	}

	return ();
}

sub _should_finalize_P2SH
{
	my ($self, $input, $input_index) = @_;

	# is there a redeem script?
	my $redeem = $self->get_all_fields('PSBT_IN_REDEEM_SCRIPT', $input_index);
	return () unless $redeem;

	my $script = $redeem->value;
	my @result = ({type => 'signature', sigs => [$script]});

	if ($script->is_native_segwit) {
		my $method = '_should_finalize_' . $script->type;

		push @result, $self->$method($input, $input_index);
	}
	elsif ($script->type eq 'P2MS') {

		# we only support P2MS

		# are there any partial signatures?
		my @partials = $self->get_all_fields('PSBT_IN_PARTIAL_SIG', $input_index);
		return () unless @partials;

		# TODO
	}

	return () unless @result > 1;
	return @result;
}

sub _should_finalize_P2WPKH
{
	my ($self, $input, $input_index) = @_;

	# are there any partial signatures?
	my @partials = $self->get_all_fields('PSBT_IN_PARTIAL_SIG', $input_index);
	return () unless @partials;

	my $wpkh = $input->utxo->output->locking_script->get_raw_address;
	foreach my $sig (@partials) {
		return ({type => 'witness', sigs => [$sig->value, $sig->key->to_serialized]})
			if $sig->key->get_hash eq $wpkh;
	}

	return ();
}

sub _should_finalize_P2WSH
{
	my ($self, $input, $input_index) = @_;

	my $redeem = $self->get_all_fields('PSBT_IN_WITNESS_SCRIPT', $input_index);
	return () unless $redeem;

	my $script = $redeem->value;

	# we only support P2MS
	return () unless $redeem->type eq 'P2MS';

	# TODO

	return (
		{type => 'witness', sigs => [$script]},
	);
}

sub _should_finalize_P2TR_keypath
{
	my ($self, $input, $input_index) = @_;

	my $sig = $self->get_all_fields('PSBT_IN_TAP_KEY_SIG', $input_index);
	return () unless $sig;

	return (
		{type => 'witness', sigs => [$sig->value]},
	);
}

sub _should_finalize_P2TR_scriptpath
{
	my ($self, $input, $input_index) = @_;

	# TODO: custom script tree - check public keys and signatures for leaves
	return ();
}

sub _should_finalize_P2TR
{
	my ($self, $input, $input_index) = @_;

	my @res = $self->_should_finalize_P2TR_keypath($input, $input_index);
	@res = $self->_should_finalize_P2TR_scriptpath($input, $input_index)
		unless @res;

	return @res;
}

sub _should_finalize
{
	my ($self, $input, $input_index) = @_;

	# is this input finalized already?
	my $signature_field = $self->get_all_fields('PSBT_IN_FINAL_SCRIPTSIG', $input_index);
	my $witness_field = $self->get_all_fields('PSBT_IN_FINAL_SCRIPTWITNESS', $input_index);
	return () if $signature_field || $witness_field;

	# custom script - unsupported
	my $type = $input->utxo->output->locking_script->type;
	return () unless defined $type;

	my $method = "_should_finalize_$type";
	return $self->$method($input, $input_index);
}

sub _finalize
{
	my ($self, $input_index, $signature, $witness) = @_;

	if (@$signature) {
		my $script = btc_script->new;

		for my $part (@$signature) {
			$script->push($part);
		}

		$self->add_field(
			type => 'PSBT_IN_FINAL_SCRIPTSIG',
			index => $input_index,
			value => $script,
		);
	}

	if (@$witness) {
		$self->add_field(
			type => 'PSBT_IN_FINAL_SCRIPTWITNESS',
			index => $input_index,
			value => $witness,
		);
	}
}

sub finalize
{
	my ($self) = @_;

	my $version = $self->version;
	my $tx = $self->get_transaction;
	my $inputs = $tx->inputs;

	foreach my $input_index (0 .. $#{$inputs}) {
		my @sig_parts = $self->_should_finalize($inputs->[$input_index], $input_index);
		next unless @sig_parts;

		my @signature;
		my @witness;
		foreach my $part (@sig_parts) {
			if ($part->{type} eq 'signature') {
				push @signature, @{$part->{sigs}};
			}
			elsif ($part->{type} eq 'witness') {
				push @witness, @{$part->{sigs}};
			}
			else {
				Bitcoin::Crypto::Exception::PSBT->raise(
					"bad finalizer type: got '$part->{type}', expected 'signature' or 'witness'"
				);
			}
		}

		$self->_finalize($input_index, \@signature, \@witness);

		# TODO remove fields other than unknowns and utxo
		# TODO check sighashes for each signature
	}
}

1;

