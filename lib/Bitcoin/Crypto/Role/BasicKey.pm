package Bitcoin::Crypto::Role::BasicKey;

use Modern::Perl "2010";
use Moo::Role;

use Bitcoin::Crypto::Helpers qw(pad_hex);
use Bitcoin::Crypto::Exception;

with "Bitcoin::Crypto::Role::Key";
with "Bitcoin::Crypto::Role::Compressed";

sub sign_message
{
	my ($self, $message, $algorithm) = @_;

	Bitcoin::Crypto::Exception::KeySign->raise(
		"cannot sign a message with a public key"
	) unless $self->_is_private;

	warn("Current implementation of signature generation mechanisms does not produce deterministic result. This is a security flaw that is currently being worked on. Please use with caution.");

	$algorithm //= "sha256";
	return $self->key_instance->sign_message($message, $algorithm);
}

sub verify_message
{
	my ($self, $message, $signature, $algorithm) = @_;
	$algorithm //= "sha256";
	return $self->key_instance->verify_message($signature, $message, $algorithm);
}

sub from_hex
{
	my ($class, $val) = @_;
	return $class->from_bytes(pack "H*", pad_hex($val));
}

sub to_hex
{
	my ($self) = @_;
	return unpack "H*", $self->to_bytes();
}

sub from_bytes
{
	my ($class, $bytes) = @_;

	return $class->new($bytes);
}

sub to_bytes
{
	my ($self) = @_;
	return $self->raw_key;
}

1;
