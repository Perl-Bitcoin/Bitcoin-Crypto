package Bitcoin::Crypto::Secret;

use v5.10;
use strict;
use warnings;

use Types::Common -types;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

our $USE_SECRET_BUFFER = $ENV{BITCOIN_CRYPTO_NO_SECRET_BUFFER}
	|| eval { require Crypt::SecretBuffer; 1; };

sub new
{
	my ($class, $secret) = @_;
	state $type_bytestr = ByteStr;
	state $type_secretbuffer = InstanceOf ['Crypt::SecretBuffer'];
	my $is_secretbuffer = $type_secretbuffer->check($secret);

	if ($USE_SECRET_BUFFER && !$is_secretbuffer) {
		$secret = Crypt::SecretBuffer->new($type_bytestr->assert_coerce($secret));
	}
	elsif (!$is_secretbuffer) {
		$secret = $type_bytestr->assert_coerce($secret);
	}

	return bless {s => $secret}, $class;
}

sub unmask_to
{
	my ($self, $sub_ref) = @_;

	# any ref accepted here is a SecretBuffer object
	if (ref $self->{s}) {
		# NOTE: for best security, sub_ref should be an XS function, but
		# Bitcoin::Crypto is not built in XS, so we take whatever extra
		# security we can get from Crypt::SecretBuffer
		return $self->{s}->unmask_to($sub_ref);
	}
	else {
		return $sub_ref->($self->{s});
	}
}

1;

