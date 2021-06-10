package Bitcoin::Crypto::Role::Key;

our $VERSION = "0.997";

use v5.10;
use warnings;
use Types::Standard qw(InstanceOf);
use Crypt::PK::ECC;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Util qw(get_key_type);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Exception;
use Moo::Role;

with "Bitcoin::Crypto::Role::Network";

has "key_instance" => (
	is => "ro",
	isa => InstanceOf ["Crypt::PK::ECC"],
	required => 1,
);

sub _is_private { undef }

sub _build_args
{
	my ($class, @params) = @_;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"invalid arguments passed to key constructor"
	) unless @params == 1;

	return
		key_instance => $class->_create_key($params[0]);
}

around BUILDARGS => sub {
	my ($orig, $class) = @_;
	my %params = $class->_build_args(splice @_, 2);

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"trying to create key from unknown key data"
	) unless $params{key_instance}->is_private() == $class->_is_private;

	return $class->$orig(%params);
};

sub _create_key
{
	my ($class, $entropy) = @_;

	return $entropy
		if blessed($entropy) && $entropy->isa("Crypt::PK::ECC");

	my $is_private = get_key_type $entropy;

	Bitcoin::Crypto::Exception::KeyCreate->raise(
		"invalid entropy data passed to key creation method"
	) unless defined $is_private;

	$entropy = ensure_length $entropy, Bitcoin::Crypto::Config::key_max_length
		if $is_private;

	my $key = Crypt::PK::ECC->new();

	Bitcoin::Crypto::Exception::KeyCreate->trap_into(
		sub {
			$key->import_key_raw($entropy, Bitcoin::Crypto::Config::curve_name);
		}
	);

	return $key;
}

sub raw_key
{
	my ($self, $type) = @_;

	unless (defined $type) {
		$type = "public_compressed";
		if ($self->_is_private) {
			$type = "private";
		}
		elsif ($self->does("Bitcoin::Crypto::Role::Compressed") && !$self->compressed) {
			$type = "public";
		}
	}
	return $self->key_instance->export_key_raw($type);
}

1;
