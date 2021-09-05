package Bitcoin::Crypto::Role::BasicKey;

our $VERSION = "1.000";

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

	Bitcoin::Crypto::Exception::Sign->raise(
		"cannot sign a message with a public key"
	) unless $self->_is_private;

	$algorithm //= "sha256";
	if (eval { require Crypt::Perl::ECDSA::Parse }) {
		$self->{_crypt_perl_prv} = Crypt::Perl::ECDSA::Parse::private($self->key_instance->export_key_der('private'))
			if !exists $self->{_crypt_perl_prv};
	}
	else {
		warn(
			'Current implementation of CryptX signature generation does not produce deterministic results. For better security, install the Crypt::Perl module.'
		);
	}

	return Bitcoin::Crypto::Exception::Sign->trap_into(
		sub {
			if (exists $self->{_crypt_perl_prv}) {
				my $sub = "sign_${algorithm}";
				return $self->{_crypt_perl_prv}->$sub($message);
			}
			else {
				return $self->key_instance->sign_message($message, $algorithm);
			}
		}
	);
}

sub verify_message
{
	my ($self, $message, $signature, $algorithm) = @_;
	verify_bytestring($signature);

	$algorithm //= "sha256";
	return Bitcoin::Crypto::Exception::Verify->trap_into(
		sub {
			$self->key_instance->verify_message($signature, $message, $algorithm);
		}
	);
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
