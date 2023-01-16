package Bitcoin::Crypto::Script::Runner;

use v5.10;
use strict;
use warnings;
use Moo;
use Mooish::AttributeBuilder -standard;

use Scalar::Util qw(blessed);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Digest::SHA1 qw(sha1);

use Bitcoin::Crypto::Types qw(ArrayRef Str PositiveOrZeroInt);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(new_bigint pad_hex hash160 hash256);

use namespace::clean;

has field 'stack' => (
	isa => ArrayRef[Str],
	writer => 1,
	default => sub { [] },
);

has field '_alt_stack' => (
	isa => ArrayRef[Str],
	writer => 1,
	default => sub { [] },
);

has field '_pos' => (
	isa => PositiveOrZeroInt,
	writer => 1,
	default => sub { 0 },
);

sub _toint
{
	my ($self, $bytes) = @_;

	return 0 if !length $bytes;

	my $negative = !!0;
	my $last = substr $bytes, -1, 1;
	my $ord = ord $last;
	if ($ord >= 0x80) {
		$negative = !!1;
		substr $bytes, -1, 1, chr($ord - 0x80);
	}

	my $value = new_bigint(scalar reverse $bytes);
	$value->bneg if $negative;

	return $value;
}

sub _fromint
{
	my ($self, $value) = @_;

	if (!blessed $value) {
		$value = Math::BigInt->new($value);
	}

	my $negative = $value < 0;
	$value->babs if $negative;

	my $bytes = reverse pack 'H*', pad_hex($value->to_hex);

	my $last = substr $bytes, -1, 1;
	my $ord = ord $last;
	if ($ord >= 0x80) {
		if ($negative) {
			$bytes .= "\x80";
		}
		else {
			$bytes .= "\x00";
		}
	}
	elsif ($negative) {
		substr $bytes, -1, 1, chr($ord + 0x80);
	}

	return $bytes;
}

sub _tobool
{
	my ($self, $bytes) = @_;

	my $len = length $bytes;
	return !!0 if $len == 0;

	my $substr = "\x00" x ($len - 1);
	return $bytes ne $substr . "\x00"
		&& $bytes ne $substr . "\x80";
}

sub _frombool
{
	my ($self, $value) = @_;

	return !!$value ? "\x01" : "\x00";
}

sub _advance
{
	my ($self, $count) = @_;
	$count //= 1;

	$self->_set_pos($self->_pos + $count);
	return;
}

sub execute
{
	my ($self, $script) = @_;

	Bitcoin::Crypto::Exception::ScriptExecute->raise(
		'invalid argument passed to script runner, not a script instance'
	) unless blessed $script && $script->isa('Bitcoin::Crypto::Script');

	$self->set_stack([]);
	$self->_set_alt_stack([]);
	$self->_set_pos(0);

	my @operations = @{$script->operations};

	Bitcoin::Crypto::Exception::ScriptRuntime->trap_into(sub {
		while ($self->_pos < @operations) {
			my ($op, @args) = @{$operations[$self->_pos]};

			$op->execute($self, @args);
			$self->_advance;
		}
	});

	return $self;
}

1;

