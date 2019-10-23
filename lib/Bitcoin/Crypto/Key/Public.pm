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
	my $pkh = $self->network->{p2pkh_byte} . $self->key_hash;
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

	return encode_segwit($self->network->{segwit_hrp}, $self->witness_program);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::Key::Public - class for Bitcoin public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::Key::Public;

	# verify signature (it has to be byte string, see perlpacktut)

	$pub->verify_message("Hello world", $sig);

	# getting address from public key (p2pkh)

	my $address = $pub->getAddress();

=head1 DESCRIPTION

This class allows you to create a public key instance.

You can use a public key to:

=over 2

=item * verify messages

=item * create p2pkh address

=back

=head1 METHODS

=head2 from_bytes

	sig: from_bytes($class, $data)
Use this method to create a PublicKey instance from a byte string.
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

=head2 set_compressed

	sig: set_compressed($self, $val)
Change key's compression state to $val (1/0). This will change the address.
If $val is omitted it is set to 1.
Returns current key instance.

=head2 set_network

	sig: set_network($self, $val)
Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. This will change
the address.
Returns current key instance.

=head2 verify_message

	sig: verify_message($self, $message, $signature, $algo = "sha256")
Verifies $signature against digest of $message (with $algo digest algorithm)
using private key.
$algo must be available in Digest package.
Returns boolean.

=head2 getAddress

	sig: getAddress($self)
Returns string containing Base58Check encoded public key hash (p2pkh address)

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::Key::Private>

=item L<Bitcoin::Crypto::Network>

=back

=cut
