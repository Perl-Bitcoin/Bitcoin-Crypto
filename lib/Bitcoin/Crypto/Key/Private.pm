package Bitcoin::Crypto::Key::Private;

use v5.10;
use strict;
use warnings;
use Moo;
use Bitcoin::BIP39 qw(bip39_mnemonic_to_entropy entropy_to_bip39_mnemonic);
use Types::Common -sigs, -types;
use List::Util qw(none);

use Bitcoin::Crypto::Key::Public;
use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Util qw(validate_wif);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Exception;

use namespace::clean;

extends qw(Bitcoin::Crypto::Key::Base);

sub _is_private { 1 }

signature_for to_wif => (
	method => Object,
	positional => [],
);

sub to_wif
{
	my ($self) = @_;
	my $bytes = $self->to_serialized();

	# wif network - 1B
	my $wifdata = $self->network->wif_byte;

	# key entropy - 32B
	$wifdata .= ensure_length $bytes, Bitcoin::Crypto::Constants::key_max_length;

	# additional byte for compressed key - 1B
	$wifdata .= Bitcoin::Crypto::Constants::wif_compressed_byte if $self->compressed;

	return encode_base58check($wifdata);
}

signature_for from_wif => (
	method => Str,
	positional => [Str, Maybe [Str], {default => undef}],
);

sub from_wif
{
	my ($class, $wif, $network) = @_;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'base58 string is not valid WIF'
	) unless validate_wif($wif);

	my $decoded = decode_base58check($wif);
	my $private = substr $decoded, 1;

	my $compressed = 0;
	if (length($private) > Bitcoin::Crypto::Constants::key_max_length) {
		chop $private;
		$compressed = 1;
	}

	my $wif_network_byte = substr $decoded, 0, 1;
	my @found_networks =
		Bitcoin::Crypto::Network->find(sub { shift->wif_byte eq $wif_network_byte });
	@found_networks = grep { $_ eq $network } @found_networks
		if defined $network;

	if (@found_networks > 1) {
		my $default_network = Bitcoin::Crypto::Network->get->id;

		Bitcoin::Crypto::Exception::KeyCreate->raise(
			'found multiple networks possible for given WIF: ' . join ', ', @found_networks
		) if none { $_ eq $default_network } @found_networks;

		@found_networks = ($default_network);
	}

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"network name $network cannot be used for given WIF"
	) if @found_networks == 0 && defined $network;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"couldn't find network for WIF byte $wif_network_byte"
	) if @found_networks == 0;

	my $instance = $class->from_serialized($private);
	$instance->set_compressed($compressed);
	$instance->set_network(@found_networks);
	return $instance;
}

signature_for get_public_key => (
	method => Object,
	positional => [],
);

sub get_public_key
{
	my ($self) = @_;

	my $public = Bitcoin::Crypto::Key::Public->new(
		key_instance => $self->raw_key('public'),
		compressed => $self->compressed,
		network => $self->network,
		purpose => $self->purpose,
	);

	return $public;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::Private - Bitcoin private keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::Private;

	# get Bitcoin::Crypto::Key::Public instance from private key

	my $pub = $priv->get_public_key();

	# automatically sign standard transactions

	$priv->sign_transaction($tx, signing_index => $n);

	# create signature for custom message (hash256)

	my $sig = $priv->sign_message('Hello world');

	# signature is returned as byte string
	# use to_format to get the representation you need

	use Bitcoin::Crypto::Util qw(to_format);
	my $sig_hex =  to_format [hex => $sig];

	# signature verification

	$priv->verify_message('Hello world', $sig);

=head1 DESCRIPTION

This class allows you to create a private key instance.

You can use a private key to:

=over

=item * generate public keys

=item * sign and verify messages

=back

Please note that any keys generated are by default compressed.

see L<Bitcoin::Crypto::Network> if you want to work with other networks than
Bitcoin Mainnet.

=head1 METHODS

=head2 new

Constructor is reserved for internal and advanced use only. Use L</from_serialized>
or L</from_wif> instead.

=head2 from_serialized

	$key_object = $class->from_serialized($serialized)

This creates a new key from string data. Argument C<$serialized> is a
formatable bytestring containing the private key entropy.

Returns a new key object instance.

=head2 to_serialized

	$serialized = $key_object->to_serialized()

This returns a private key as a sequence of bytes. The result is a bytestring
which can be further formated with C<to_format> utility.

=head2 from_bytes

Deprecated. Use C<< $class->from_serialized($data) >> instead.

=head2 to_bytes

Deprecated. Use C<< $key->to_serialized() >> instead.

=head2 from_hex

Deprecated. Use C<< $class->from_serialized([hex => $data]) >> instead.

=head2 to_hex

Deprecated. Use C<< to_format [hex => $key->to_serialized()] >> instead.

=head2 from_wif

	$key_object = $class->from_wif($str, $network = undef)

Creates a new private key from Wallet Import Format string.

Takes an additional optional argument, which is network name. It may be useful
if you use many networks and some have the same WIF byte.

This method will change compression and network states of the created private
key, as this data is included in WIF format.

Returns class instance.

=head2 to_wif

	$wif_string = $object->to_wif()

Does the opposite of from_wif on a target object

=head2 set_compressed

	$key_object = $object->set_compressed($val)

Change key's compression state to C<$val> (1/0). This will change the WIF
generated by to_wif() method and also enable creation of uncompressed public
keys. If C<$val> is omitted it is set to C<1>.

Returns current key instance.

=head2 set_network

	$key_object = $object->set_network($val)

Change key's network state to C<$val>. It can be either network name present in
Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 get_public_key

	$public_key_object = $object->get_public_key()

Returns instance of L<Bitcoin::Crypto::Key::Public> generated from the private
key.

=head2 sign_message

	$signature = $object->sign_message($message)

Signs a digest of C<$message> (digesting it with double sha256) with a private
key.

Returns a byte string containing signature.

Character encoding note: C<$message> should be encoded in the proper encoding
before passing it to this method. Passing Unicode string will cause the
function to fail. You can encode like this (for UTF-8):

	use Encode qw(encode);
	$message = encode('UTF-8', $message);

=head2 sign_transaction

	$object->sign_transaction($tx, %params)

Signs the transaction C<$tx> using this private key. This automatic signing
only works for standard script types, if your script is non-standard then you
will have to sign manually.

Note that the module will let you sign any transaction with any private key.
You have to manually run L<Bitcoin::Crypto::Transaction/verify> to ensure you
used the right private key and the signature is correct for the corresponding
locking script.

Returns nothing - the result of the function is the modification of transaction
C<$tx>.

C<%params> can contain:

=over

=item * C<signing_index>

This non-negative integer is the index of the input being signed. Required.

=item * C<redeem_script>

A L<Bitcoin::Crypto::Script> instance or something which can be turned into a
script, used for specifying a payout script when redeeming P2SH and P2WSH
outputs.

=item * C<multisig>

A representation of the multisig signing stage. It is an array reference with
exactly two elements. The first element is the number (1-based, not the index!)
of the currently signed multisig. The second element is the total number of
signatures required for the multisig. For example, signing 2-out-of-3 multisig
can look like this (taken from C<ex/tx/multisig_redeem.pl> example):

	# sign using the private key belonging to the first pubkey
	btc_prv->from_wif('cScAuqNfiNR7mq61QGW3LtokKAwzBzs4rbCz4Uff1NA15ysEij2i')
		->sign_transaction($tx, signing_index => 0, redeem_script => $redeem_script, multisig => [1, 2]);

	# sign using the private key belonging to the third pubkey
	btc_prv->from_wif('cQsSKWrBLXNY1oSZbLcJf4HF5vnKGgKko533LnkTmqRdS9Fx4SGH')
		->sign_transaction($tx, signing_index => 0, redeem_script => $redeem_script, multisig => [2, 2]);

=item * C<sighash>

The sighash which should be used for the signature. By default C<SIGHASH_ALL>
is used.

=back

=head2 verify_message

	$signature_valid = $object->verify_message($message, $signature)

Verifies C<$signature> against digest of C<$message> (digesting it with double
sha256) using private key.

Returns boolean.

Character encoding note: C<$message> should be encoded in the proper encoding
before passing it to this method. Passing Unicode string will cause the
function to fail. You can encode like this (for UTF-8):

	use Encode qw(encode);
	$message = encode('UTF-8', $message);

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it
encounters an error. It can produce the following error types from the
L<Bitcoin::Crypto::Exception> namespace:

=over

=item * Sign - couldn't sign the message correctly

=item * ScriptType - couldn't automatically sign the given script type

=item * Verify - couldn't verify the message correctly

=item * KeyCreate - key couldn't be created correctly

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over

=item L<Bitcoin::Crypto::Key::Public>

=item L<Bitcoin::Crypto::Network>

=back

=cut

