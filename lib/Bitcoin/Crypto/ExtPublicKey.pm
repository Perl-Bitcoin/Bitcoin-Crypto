package Bitcoin::Crypto::ExtPublicKey;

use Modern::Perl "2010";
use Moo;
use Digest::SHA qw(hmac_sha512);
use Carp qw(croak);
use Math::BigInt 1.999816 try => 'GMP';
use Math::EllipticCurve::Prime;
use Math::EllipticCurve::Prime::Point;

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Helpers qw(ensure_length);

with "Bitcoin::Crypto::Roles::ExtendedKey";

sub _isPrivate { 0 }

sub _deriveKeyPartial
{
	my ($self, $child_num, $hardened) = @_;

	croak {reason => "key_derive", message => "cannot derive hardened key from public key"}
		if $hardened;

	# public key data - SEC compressed form
	my $hmac_data = $self->rawKey("public_compressed");
	# child number - 4 bytes
	$hmac_data .= ensure_length pack("N", $child_num), 4;

	my $data = hmac_sha512($hmac_data, $self->chainCode);
	my $chain_code = substr $data, 32, 32;

	my $el_curve = Math::EllipticCurve::Prime->from_name($config{curve_name});
	my $number = Math::BigInt->from_bytes(substr $data, 0, 32);
	my $key = $self->_createKey(substr $data, 0, 32);
	my $point = Math::EllipticCurve::Prime::Point->from_bytes($key->export_key_raw("public"));
	$point->curve($el_curve);
	my $point_cpy = $point->copy();
	my $parent_point = Math::EllipticCurve::Prime::Point->from_bytes($self->rawKey("public"));
	$parent_point->curve($el_curve);
	my $n_order = $el_curve->n;

	$point->badd($parent_point);

	croak {reason => "key_derive", message => "key $child_num in sequence was found invalid"}
		if $number->bge($n_order);

	return __PACKAGE__->new(
		$point->to_bytes,
		$chain_code,
		$child_num,
		$self->getFingerprint,
		$self->depth + 1
	);
}

1;


__END__
=head1 NAME

Bitcoin::Crypto::ExtPublicKey - class for Bitcoin extended public keys

=head1 SYNOPSIS

	use Bitcoin::Crypto::ExtPrivateKey;

	my $mnemonic = Bitcoin::Crypto::ExtPrivateKey->generateMnemonic;
	my $key = Bitcoin::Crypto::ExtPrivateKey->fromMnemonic($mnemonic);

	# derive child public key
	my $path = "M/0";
	my $child_key = $key->deriveKey($path);
	my $ser_child_key = $child_key->toSerializedBase58;
	print "Your exported $path child key is: $ser_child_key";

	# create basic public key
	my $basic_public = $child_key->getBasicKey;

=head1 DESCRIPTION

This class allows you to create an extended public key instance.

You can use an extended public key to:

=over 2

=item * derive extended keys using a path (only public keys)

=item * restore keys from serialized base58 format

=back

see L<Bitcoin::Crypto::Network> if you want to work with other networks than Bitcoin Mainnet.

=head1 METHODS

=head2 toSerialized

	sig: toSerialized($self)
Returns the key serialized in format specified in BIP32 as byte string.

=head2 toSerializedBase58

	sig: toSerializedBase58($self)
Behaves the same as toSerialized(), but performs Base58Check encoding
on the resulting byte string.

=head2 fromSerialized

	sig: fromSerialized($class, $serialized, $network = undef)
Tries to unserialize byte string $serialized with format specified in BIP32.
Croaks on errors. If multiple networks match serialized data specify $network
manually (id of the network) to avoid exception.

=head2 fromSerializedBase58

	sig: fromSerializedBase58($class, $base58, $network)
Same as fromSerialized, but performs Base58Check decoding on $base58 argument.

=head2 setNetwork

	sig: setNetwork($self, $val)
Change key's network state to $val. It can be either network name present in
Bitcoin::Crypto::Network package or a valid network hashref.
Returns current key instance.

=head2 getBasicKey

	sig: getBasicKey($self)
Returns the key in basic format: L<Bitcoin::Crypto::PrivateKey>

=head2 deriveKey

	sig: deriveKey($self, $path)
Performs extended key deriviation as specified in BIP32 on the current key
with $path. Croaks on error.
See BIP32 document for details on deriviation paths and methods.
Note that public keys cannot derive private keys and your deriviation
path must start with M (capital m).
Returns a new extended key instance - result of a deriviation.

=head2 getFingerprint

	sig: getFingerprint($self, $len = 4)
Returns a fingerprint of the extended key of $len length (byte string)

=head1 SEE ALSO

=over 2

=item L<Bitcoin::Crypto::ExtPrivateKey>

=item L<Bitcoin::Crypto::Network>

=back

=cut
