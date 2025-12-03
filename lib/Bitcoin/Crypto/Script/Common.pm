package Bitcoin::Crypto::Script::Common;

use v5.14;
use warnings;

use Types::Common -sigs, -types;
use namespace::autoclean;

use Bitcoin::Crypto qw(btc_script btc_tapscript);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

sub _make_PKH
{
	my ($class, $script, $hash) = @_;
	$script //= btc_script->new;

	return $script
		->add('OP_DUP')
		->add('OP_HASH160')
		->push($hash)
		->add('OP_EQUALVERIFY')
		->add('OP_CHECKSIG');
}

sub _make_SH
{
	my ($class, $script, $hash) = @_;
	$script //= btc_script->new;

	return $script
		->add('OP_HASH160')
		->push($hash)
		->add('OP_EQUAL');
}

sub _make_WSH
{
	my ($class, $script, $hash) = @_;
	$script //= btc_script->new;

	return $script
		->add('OP_SHA256')
		->push($hash)
		->add('OP_EQUAL');
}

sub _make_TR
{
	my ($class, $script, $pubkey) = @_;
	$script //= btc_tapscript->new;

	return $script
		->push($pubkey)
		->add('OP_CHECKSIG');
}

sub _get_method
{
	my ($class, $type) = @_;

	my $method = '_make_' . $type;
	Bitcoin::Crypto::Exception::ScriptType->raise(
		"cannot create common script of type $type"
	) unless $class->can($method);

	return $method;
}

signature_for new => (
	method => Str,
	positional => [Str, ByteStr],
);

sub new
{
	my ($class, $type, $data) = @_;

	return $class->fill($type, undef, $data);
}

signature_for fill => (
	method => Str,
	positional => [Str, Maybe [BitcoinScript], ByteStr],
);

sub fill
{
	my ($class, $type, $script, $data) = @_;

	my $method = $class->_get_method($type);
	return $class->$method($script, $data);
}

1;

