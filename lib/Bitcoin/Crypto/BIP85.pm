package Bitcoin::Crypto::BIP85;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -sigs, -types;
use List::Util qw(all);
use Crypt::Mac::HMAC qw(hmac);

use Bitcoin::Crypto::Util qw(get_path_info);
use Bitcoin::Crypto::Exception;

use namespace::clean;

has param 'key' => (
	isa => InstanceOf ['Bitcoin::Crypto::Key::ExtPrivate'],
);

signature_for derive_entropy => (
	method => Object,
	positional => [Str | Object],
);

sub derive_entropy
{
	my ($self, $path) = @_;
	my $path_info = get_path_info $path;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		'invalid seed derivation path supplied'
	) unless defined $path_info;

	Bitcoin::Crypto::Exception::KeyDerive->raise(
		'seed derivation path must be fully hardened'
	) unless all { !!$_ } @{$path_info->get_hardened};

	my $key = $self->key->derive_key($path_info);

	my $seed = hmac('SHA512', "bip-entropy-from-k", $key->raw_key('private'));
	return $seed;
}

1;

__END__
=head1 NAME

Bitcoin::Crypto::BIP85 - BIP85 (deterministic entropy) implementation

=head1 SYNOPSIS

	use Bitcoin::Crypto::BIP85;

	my $bip85 = Bitcoin::Crypto::BIP85->new(
		key => $extended_private_key,
	);

	# get raw bytestring seed
	my $seed = $bip85->derive_entropy("m/0'/0'");

=head1 DESCRIPTION

This module implements
L<BIP85|https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki>,
enabling deterministic seed generation from a master key.

=head1 INTERFACE

=head2 Attributes

=head3 key

B<Required in the constructor.> The master key from which the generation will
be performed, an instance of L<Bitcoin::Crypto::Key::ExtPrivate>.

=head2 Methods

=head3 new

	$bip_object = $class->new(%data)

This is a standard Moo constructor, which can be used to create the object. It
takes arguments specified in L</Attributes>.

=head3 derive_entropy

	$bytestr = $object->derive_entropy($path)

Returns full C<512> bytes of entropy derived from the master key using
C<$path>, which can be a standard string derivation path like
C<m/83696968'/0'/0'> or an instance of L<Bitcoin::Crypto::DerivationPath>. The
derivation path must be fully hardened, as specified in the BIP.

