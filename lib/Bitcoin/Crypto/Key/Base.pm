package Bitcoin::Crypto::Key::Base;

use v5.14;
use warnings;

use Mooish::Base -standard;
use Types::Common -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Util::Internal qw(to_format tagged_hash lift_x has_even_y);
use Bitcoin::Crypto::Helpers qw(ecc);

has param 'taproot_output' => (
	isa => Bool,
	writer => 1,
	default => !!0,
);

with qw(
	Bitcoin::Crypto::Role::Key
	Bitcoin::Crypto::Role::Compressed
	Bitcoin::Crypto::Role::SignVerify
);

sub _is_private
{
	die __PACKAGE__ . '::_is_private is unimplemented';
}

sub from_serialized
{
	my ($class, $data) = @_;

	return $class->new(_key_instance => $data);
}

sub to_serialized
{
	my ($self) = @_;

	return $self->raw_key;
}

signature_for get_taproot_output_key => (
	method => !!1,
	positional => [Maybe [ByteStr], {default => undef}],
);

sub get_taproot_output_key
{
	my ($self, $tweak_suffix) = @_;

	return $self if $self->taproot_output;

	my $new_key;
	if ($self->_is_private) {
		my $internal = $self->raw_key('private');
		my $internal_public = ecc->create_public_key($internal);
		$internal = ecc->negate_private_key($internal)
			unless has_even_y($internal_public);

		my $tweak = tagged_hash('TapTweak', ecc->xonly_public_key($internal_public) . ($tweak_suffix // ''));
		$new_key = ecc->add_private_key($internal, $tweak);
	}
	else {
		my $internal = $self->raw_key('public_xonly');
		my $tweak = tagged_hash('TapTweak', $internal . ($tweak_suffix // ''));
		$new_key = ecc->combine_public_keys(ecc->create_public_key($tweak), lift_x $internal);
	}

	my $pkg = ref $self;
	return $pkg->new(
		_key_instance => $new_key,
		purpose => $self->purpose,
		network => $self->network,
		taproot_output => !!1,
	);
}

1;

# Internal use only

