package Bitcoin::Crypto::Role::Key;

use Modern::Perl "2010";
use Moo::Role;
use MooX::Types::MooseLike::Base qw(InstanceOf);
use Crypt::PK::ECC;
use Carp qw(croak);

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Util qw(get_key_type);
use Bitcoin::Crypto::Helpers qw(ensure_length);

with "Bitcoin::Crypto::Role::Network";

has "keyInstance" => (
	is => "ro",
	isa => InstanceOf["Crypt::PK::ECC"]
);

sub _isPrivate { undef }

sub _buildArgs
{
	my ($class, @params) = @_;

	croak {reason => "key_create", message => "invalid arguments passed to key constructor"}
		unless @params == 1;

	return
		keyInstance => $class->_createKey($params[0]);
}

around BUILDARGS => sub {
	my ($orig, $class) = @_;
	my %params = $class->_buildArgs(splice @_, 2);

	croak {reason => "key_create", message => "trying to create key from unknown key data"}
		unless $params{keyInstance}->is_private() == $class->_isPrivate;

	return $class->$orig(%params);
};

sub _createKey
{
	my ($class, $entropy) = @_;

	my $key_type = get_key_type $entropy;
	unless (defined $key_type) {
		croak {reason => "key_create", message => "invalid entropy data passed to key creation method"}
			if length $entropy > $config{key_max_length};
		$entropy = ensure_length $entropy, $config{key_max_length};
	}

	my $key = Crypt::PK::ECC->new();
	$key->import_key_raw($entropy, $config{curve_name});

	return $key;
}

sub rawKey
{
	my ($self, $type) = @_;

	unless (defined $type) {
		$type = "public_compressed";
		if ($self->_isPrivate) {
			$type = "private";
		} elsif ($self->does("Bitcoin::Crypto::Role::Compressed") && !$self->compressed) {
			$type = "public";
		}
	}
	return $self->keyInstance->export_key_raw($type);
}

1;
