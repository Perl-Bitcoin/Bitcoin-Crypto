package Bitcoin::Crypto::Role::BasicKey;

our $VERSION = "0.996";

use v5.10;
use warnings;

use Bitcoin::Crypto::Helpers qw(pad_hex verify_bytestring);
use Bitcoin::Crypto::Exception;
use Moo::Role;

with "Bitcoin::Crypto::Role::Key",
	"Bitcoin::Crypto::Role::Compressed";

sub sign_message
{
	my ($self, $message, $algorithm) = @_;

	Bitcoin::Crypto::Exception::KeySign->raise(
		"cannot sign a message with a public key"
	) unless $self->_is_private;

	warn(
		"Current implementation of signature generation mechanisms does not produce deterministic result. This is a security flaw that is currently being worked on. Please use with caution."
	);

	$algorithm //= "sha256";
	return $self->key_instance->sign_message($message, $algorithm);
}

sub verify_message
{
	my ($self, $message, $signature, $algorithm) = @_;
	verify_bytestring($signature);

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
	verify_bytestring($bytes);

	return $class->new($bytes);
}

sub to_bytes
{
	my ($self) = @_;
	return $self->raw_key;
}

1;
