package Bitcoin::Crypto::Roles::BasicKey;

use Modern::Perl "2010";
use Moo::Role;
use Carp qw(croak);

use Bitcoin::Crypto::Helpers qw(pad_hex);

with "Bitcoin::Crypto::Roles::Key";
with "Bitcoin::Crypto::Roles::Compressed";

sub signMessage
{
	my ($self, $message, $algorithm) = @_;
	croak "Cannot sign a message with a public key"
		unless $self->_isPrivate;
	$algorithm //= "sha256";
	return $self->keyInstance->sign_message($message, $algorithm);
}

sub verifyMessage
{
	my ($self, $message, $signature, $algorithm) = @_;
	$algorithm //= "sha256";
	return $self->keyInstance->verify_message($signature, $message, $algorithm);
}

sub fromHex
{
	my ($class, $val) = @_;
	return $class->fromBytes(pack "H*", pad_hex($val));
}

sub toHex
{
	my ($self) = @_;
	return unpack "H*", $self->toBytes();
}

sub fromBytes
{
	my ($class, $bytes) = @_;

	return $class->new($bytes);
}

sub toBytes
{
	my ($self) = @_;
	return $self->rawKey;
}

1;