package Bitcoin::Crypto::Key::Public;

use Modern::Perl "2010";
use Moo;

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Base58 qw(encode_base58check);
use Bitcoin::Crypto::Bech32 qw(encode_segwit);
use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(hash160);

with "Bitcoin::Crypto::Role::BasicKey";

sub _is_private { 0 }

sub key_hash
{
	my ($self) = @_;
	my $pubkey = $self->to_bytes();
	return hash160($pubkey);
}

sub witness_program
{
	my ($self) = @_;

	return pack("C", $config{witness_version}) . $self->key_hash;
}

sub get_legacy_address
{
	my ($self) = @_;
	my $pkh = $self->network->p2pkh_byte . $self->key_hash;
	return encode_base58check($pkh);
}

sub get_compat_address
{
	my ($self) = @_;

	my $program = Bitcoin::Crypto::Script->new(network => $self->network);
	$program->add_operation("OP_" . $config{witness_version})
		->push_bytes($self->key_hash);
	return $program->get_legacy_address;
}

sub get_segwit_address
{
	my ($self) = @_;

	# network field is not required, lazy check for completeness
	Bitcoin::Crypto::Exception::NetworkConfig->raise(
		"no segwit_hrp found in network configuration"
	) unless defined $self->network->segwit_hrp;

	return encode_segwit($self->network->segwit_hrp, $self->witness_program);
}

no Moo;
1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::Public - class for Bitcoin public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::Public;

	$pub = Bitcoin::Crypto::Key::Public->from_hex($asn_hex);

	# verify signature (it has to be byte string, see perlpacktut)

	$pub->verify_message(pack("a*", "Hello world"), $sig);

	# getting address from public key (p2wpkh)

	my $address = $pub->get_segwit_address();

=head1 DESCRIPTION

This class allows you to create a public key instance.

You can use a public key to:

=over 2

=item * verify messages

=item * create addresses: legacy (p2pkh), compatibility (p2sh(p2wpkh)) and segwit (p2wpkh).

=back

=head1 METHODS

=head2 from_bytes

	sig: from_bytes($class, $data)

Use this method to create a PublicKey instance from a byte string.
Data $data must represent a public key in ASN X9.62 format.

Returns class instance.

=head2 new

	sig: new($class, $data)

This works exactly the same as from_bytes

=head2 to_bytes

	sig: to_bytes($self)

Does the opposite of from_bytes on a target object

=head2 from_hex

	sig: from_hex($class, $hex)

Use this method to create a public key instance from a hexadecimal number. Packs the number and runs it through from_bytes.

Returns class instance.

=head2 to_hex

	sig: to_hex($self)

Does the opposite of from_hex on a target object

=head2 set_compressed

	sig: set_compressed($self, $val)

Change key's compression state to $val (1/0). This will change the address.
If $val is omitted it is set to 1.

Returns current key instance.

=head2 set_network

	sig: set_network($self, $val)

Change key's network state to $val. It can be either network name present in Bitcoin::Crypto::Network package or an instance of this class.

Returns current key instance.

=head2 verify_message

	sig: verify_message($self, $message, $signature, $algo = "sha256")

Verifies $signature against digest of $message (with $algo digest algorithm) using public key.
$algo must be available in Digest package.

Returns boolean.

=head2 get_legacy_address

	sig: get_legacy_address($self)

Returns string containing Base58Check encoded public key hash (p2pkh address)

=head2 get_compat_address

	sig: get_compat_address($self)

Returns string containing Base58Check encoded script hash containing a witness program for compatibility purposes (p2sh(p2wpkh) address)

=head2 get_segwit_address

	sig: get_segwit_address($self)

Returns string containing Bech32 encoded witness program (p2wpkh address)

=head1 EXCEPTIONS

This module throws an instance of L<Bitcoin::Crypto::Exception> if it encounters an error. It can produce the following error types from the L<Bitcoin::Crypto::Exception> namespace:

=over 2

=item * KeyCreate - key couldn't be created correctly

=item * NetworkConfig - incomplete or corrupted network configuration

=back

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Network>

=item L<Bitcoin::Crypto::Base58>

=item L<Bitcoin::Crypto::Bech32>

=back

=cut
