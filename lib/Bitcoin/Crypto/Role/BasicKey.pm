package Bitcoin::Crypto::Role::BasicKey;

use Modern::Perl "2010";
use Moo::Role;

use Bitcoin::Crypto::Helpers qw(pad_hex);
use Bitcoin::Crypto::Exception;

with "Bitcoin::Crypto::Role::Key";
with "Bitcoin::Crypto::Role::Compressed";

sub signMessage
{
	my ($self, $message, $algorithm) = @_;

	Bitcoin::Crypto::Exception->raise(
		code => "key_sign",
		message => "cannot sign a message with a public key"
	) unless $self->_isPrivate;

	Bitcoin::Crypto::Exception->warn(
		code => "key_sign",
		message => "Current implementation of signature generation mechanisms does not produce deterministic result. This is a security flaw that is currently being worked on. Please use with caution."
	);

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
