package Bitcoin::Crypto::PublicKey;

use Modern::Perl "2010";
use Moo;
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Digest::SHA qw(sha256);
use Carp qw(croak);

use Bitcoin::Crypto::Base58 qw(encode_base58check);

with "Bitcoin::Crypto::Roles::BasicKey";

sub _isPrivate { 0 }

sub getAddress
{
	my ($self) = @_;
	my $pubkey = $self->toBytes();
	my $pkh = pack("C", $self->network->{p2pkh_byte}) . ripemd160(sha256($pubkey));
	return encode_base58check($pkh);
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::PublicKey - class for Bitcoin public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::PublicKey;

	# verify signature (it has to be byte string, see perlpacktut)

	$pub->verifyMessage("Hello world", $sig);

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

=head2 fromBytes

	sig: fromBytes($class, $data)
Use this method to create a PublicKey instance from a byte string.
Data $data will be used as a private key entropy.
Returns class instance.

=head2 new

	sig: new($class, $data)
This works exactly the same as fromBytes

=head2 toBytes

	sig: toBytes($self)
Does the opposite of fromBytes on a target object

=head2 fromHex

	sig: fromHex($class, $hex)
Use this method to create a PrivateKey instance from a hexadecimal number.
Number $hex will be used as a private key entropy.
Returns class instance.

=head2 toHex

	sig: toHex($self)
Does the opposite of fromHex on a target object

=head2 setCompressed

	sig: setCompressed($self, $val)
Change key's compression state to $val (1/0). This will change the address.
If $val is omitted it is set to 1.
Returns current key instance.

=head2 setNetwork

	sig: setNetwork($self, $val)
Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref. This will change
the address.
Returns current key instance.

=head2 verifyMessage

	sig: verifyMessage($self, $message, $signature, $algo = "sha256")
Verifies $signature against digest of $message (with $algo digest algorithm)
using private key.
$algo must be available in Digest package.
Returns boolean.

=head2 getAddress

	sig: getAddress($self)
Returns string containing Base58Check encoded public key hash (p2pkh address)

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::PrivateKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut