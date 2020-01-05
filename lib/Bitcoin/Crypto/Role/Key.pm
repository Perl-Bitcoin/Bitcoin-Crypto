package Bitcoin::Crypto::Role::Key;

use Modern::Perl "2010";
use Moo::Role;
use MooX::Types::MooseLike::Base qw(InstanceOf);
use Crypt::PK::ECC;

use Bitcoin::Crypto::Config;
use Bitcoin::Crypto::Util qw(get_key_type);
use Bitcoin::Crypto::Helpers qw(ensure_length);
use Bitcoin::Crypto::Exception;

with "Bitcoin::Crypto::Role::Network";

has "key_instance" => (
	is => "ro",
	isa => InstanceOf["Crypt::PK::ECC"]
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

	my $key_type = get_key_type $entropy;
	unless (defined $key_type) {
		Bitcoin::Crypto::Exception::KeyCreate->raise(
			"invalid entropy data passed to key creation method"
		) if length $entropy > $config{key_max_length};

		$entropy = ensure_length $entropy, $config{key_max_length};
	}

	my $key = Crypt::PK::ECC->new();
	$key->import_key_raw($entropy, $config{curve_name});

	return $key;
}

sub raw_key
{
	my ($self, $type) = @_;

	unless (defined $type) {
		$type = "public_compressed";
		if ($self->_is_private) {
			$type = "private";
		} elsif ($self->does("Bitcoin::Crypto::Role::Compressed") && !$self->compressed) {
			$type = "public";
		}
	}
	return $self->key_instance->export_key_raw($type);
}

1;
