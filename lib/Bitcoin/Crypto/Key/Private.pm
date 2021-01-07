package Bitcoin::Crypto::Key::Private;

our $VERSION = "0.996";

use v5.10;
use warnings;
use Moo;
use Types::Standard qw(Str);
use Crypt::PK::ECC;
use Bitcoin::BIP39 qw(bip39_mnemonic_to_entropy entropy_to_bip39_mnemonic);
use List::Util qw(first);

use Bitcoin::Crypto::Key::Public;
use Bitcoin::Crypto::Base58 qw(encode_base58check decode_base58check);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Util qw(validate_wif);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto;

use namespace::clean;
our $VERSION = Bitcoin::Crypto->VERSION;

with "Bitcoin::Crypto::Role::BasicKey";

sub _is_private { 1 }

sub to_wif
{
	my ($self) = @_;
	my $bytes = $self->to_bytes();

	# wif network - 1B
	my $wifdata = $self->network->wif_byte;

	# key entropy - 32B
	$wifdata .= ensure_length $bytes, $config{key_max_length};

	# additional byte for compressed key - 1B
	$wifdata .= $config{wif_compressed_byte} if $self->compressed;

	return encode_base58check($wifdata);
}

sub from_wif
{
	my ($class, $wif, $network) = @_;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"base58 string is not valid WIF"
	) unless validate_wif($wif);

	my $decoded = decode_base58check($wif);
	my $private = substr $decoded, 1;

	my $compressed = 0;
	if (length($private) > $config{key_max_length}) {
		chop $private;
		$compressed = 1;
	}

	my $wif_network_byte = substr $decoded, 0, 1;
	my @found_networks =
		Bitcoin::Crypto::Network->find(sub { shift->wif_byte eq $wif_network_byte });
	@found_networks = first { $_ eq $network }
		@found_networks if defined $network;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"found multiple networks possible for given WIF"
	) if @found_networks > 1;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"network name $network cannot be used for given WIF"
	) if @found_networks == 0 && defined $network;

	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"couldn't find network for WIF byte $wif_network_byte"
	) if @found_networks == 0;

	my $instance = $class->from_bytes($private);
	$instance->set_compressed($compressed);
	$instance->set_network(@found_networks);
	return $instance;
}

sub get_public_key
{
	my ($self) = @_;

	my $public = Bitcoin::Crypto::Key::Public->new($self->raw_key("public"));
	$public->set_compressed($self->compressed);
	$public->set_network($self->network);
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

	# create signature using private key (sha256 of string byte representation)

	my $sig = $priv->sign_message("Hello world");

	# signature is returned as byte string
	# use unpack to get the representation you need

	my $sig_hex = unpack "H*", $sig;

	# signature verification

	$priv->verify_message("Hello world", $sig);

=head1 DESCRIPTION

This class allows you to create a private key instance.

You can use a private key to:

=over 2

=item * generate public keys

=item * sign and verify messages

=back

Please note that any keys generated are by default compressed.

see L<Bitcoin::Crypto::Network> if you want to work with other networks than Bitcoin Mainnet.

=head1 METHODS

=head2 from_bytes

	sig: from_bytes($class, $data)

Use this method to create a PrivateKey instance from a byte string.
Data $data will be used as a private key entropy.

Returns class instance.

=head2 new

	sig: new($class, $data)

This works exactly the same as from_bytes

=head2 to_bytes

	sig: to_bytes($self)

Does the opposite of from_bytes on a target object

=head2 from_hex

	sig: from_hex($class, $hex)

Use this method to create a PrivateKey instance from a hexadecimal number.
Number $hex will be used as a private key entropy.

Returns class instance.

=head2 to_hex

	sig: to_hex($self)

Does the opposite of from_hex on a target object

=head2 from_wif

	sig: from_wif($class, $str, $network = undef)

Creates a new private key from Wallet Import Format string.

Takes an additional optional argument, which is network name. It may be useful if you use many networks and some have the same WIF byte.

This method will change compression and network states of the created private key, as this data is included in WIF format.

Returns class instance.

=head2 to_wif

	sig: to_wif($self)

Does the opposite of from_wif on a target object

=head2 set_compressed

	sig: set_compressed($self, $val)

Change key's compression state to $val (1/0). This will change the WIF generated by
toWif() method and also enable creation of uncompressed public keys.
If $val is omitted it is set to 1.

Returns current key instance.

=head2 set_network

	sig: set_network($self, $val)

Change key's network state to $val. It can be either network name present in Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 get_public_key

	sig: get_public_key($self)

Returns instance of L<Bitcoin::Crypto::PublicKey> generated from the private key.

=head2 sign_message

	sig: sign_message($self, $message, $algo = "sha256")

Signs a digest of $message (using $algo digest algorithm) with a private key.

$algo must be available in L<Digest> package.

Returns a byte string containing signature.

Caution: libtomcrypt cryptographic package that is generating signatures does not currently offer a deterministic mechanism. For this reason the sign_message method will always complain with a warning until the RFC6797 procedure is implemented. Non-deterministic signatures can lead to leaking private keys if the random number generator's entropy is insufficient.

=head2 verify_message

	sig: verify_message($self, $message, $signature, $algo = "sha256")

Verifies $signature against digest of $message (with $algo digest algorithm) using private key.
$algo must be available in Digest package.
Returns boolean.

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * KeySign - couldn't sign the message corretcly

=item * KeyCreate - key couldn't be created correctly

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::Public>

=item L<Bitcoin::Crypto::Network>

=back

=cut
