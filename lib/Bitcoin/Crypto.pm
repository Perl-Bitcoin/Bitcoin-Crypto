package Bitcoin::Crypto;

use v5.10;
use strict;
use warnings;
use Exporter qw(import);

our @EXPORT_OK = qw(
	btc_extprv
	btc_prv
	btc_extpub
	btc_pub
	btc_script
	btc_transaction
	btc_block
	btc_utxo
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

sub btc_extprv
{
	require Bitcoin::Crypto::Key::ExtPrivate;
	return 'Bitcoin::Crypto::Key::ExtPrivate';
}

sub btc_prv
{
	require Bitcoin::Crypto::Key::Private;
	return 'Bitcoin::Crypto::Key::Private';
}

sub btc_extpub
{
	require Bitcoin::Crypto::Key::ExtPublic;
	return 'Bitcoin::Crypto::Key::ExtPublic';
}

sub btc_pub
{
	require Bitcoin::Crypto::Key::Public;
	return 'Bitcoin::Crypto::Key::Public';
}

sub btc_script
{
	require Bitcoin::Crypto::Script;
	return 'Bitcoin::Crypto::Script';
}

sub btc_transaction
{
	require Bitcoin::Crypto::Transaction;
	return 'Bitcoin::Crypto::Transaction';
}

sub btc_utxo
{
	require Bitcoin::Crypto::Transaction::UTXO;
	return 'Bitcoin::Crypto::Transaction::UTXO';
}

sub btc_block
{
	require Bitcoin::Crypto::Block;
	return 'Bitcoin::Crypto::Block';
}

__END__

=head1 NAME

Bitcoin::Crypto - Bitcoin cryptography in Perl

=head1 SYNOPSIS

	use Bitcoin::Crypto qw(btc_extprv);
	use Bitcoin::Crypto::Util qw(generate_mnemonic to_format);
	use Bitcoin::Crypto::Constants;

	# extended keys are used for mnemonic generation and key derivation
	my $mnemonic = generate_mnemonic;
	say "your mnemonic code is: $mnemonic";

	my $master_key = btc_extprv->from_mnemonic($mnemonic);
	my $derived_key = $master_key->derive_key_bip44(
		purpose => Bitcoin::Crypto::Constants::bip44_segwit_purpose,
		index => 0,
	);

	# basic keys can be used for signatures and addresses
	my $priv = $derived_key->get_basic_key;
	my $pub = $priv->get_public_key;

	say 'private key: ' . $priv->to_wif;
	say 'public key: ' . to_format [hex => $pub->to_serialized];
	say 'address: ' . $pub->get_address;

=head1 DESCRIPTION

Cryptographic module for common Bitcoin-related tasks.

See L<Bitcoin::Crypto::Manual> for an overview of the module.

=head1 SHORTCUT FUNCTIONS

=head2 Exported interface

This package exports the following functions when asked for them. These are
shourtcut functions and will load needed packages and return their names. You
can then use names of loaded packages to instantiate them however you want. You
can also load all of them with the I<:all> tag in import. These functions can
be used as follows:

	use Bitcoin::Crypto qw(btc_pub);

	# loads Bitcoin::Crypto::Key::Public and returns package name
	# we can now use it to run its methods
	my $public_key = btc_pub->from_serialized([hex => $hex_data]);

=head3 btc_extprv

Loads L<Bitcoin::Crypto::Key::ExtPrivate>

=head3 btc_prv

Loads L<Bitcoin::Crypto::Key::Private>

=head3 btc_extpub

Loads L<Bitcoin::Crypto::Key::ExtPublic>

=head3 btc_pub

Loads L<Bitcoin::Crypto::Key::Public>

=head3 btc_script

Loads L<Bitcoin::Crypto::Script>

=head3 btc_transaction

Loads L<Bitcoin::Crypto::Transaction>

=head3 btc_utxo

Loads L<Bitcoin::Crypto::Transaction::UTXO>

=head3 btc_block

Loads L<Bitcoin::Crypto::Block>

=head1 SEE ALSO

L<Bitcoin::RPC::Client>

L<https://github.com/bitcoin/bips>

=head1 AUTHOR

Bartosz Jarzyna E<lt>bbrtj.pro@gmail.comE<gt> (L<Support me|https://bbrtj.eu/support>)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2018 - 2023 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

