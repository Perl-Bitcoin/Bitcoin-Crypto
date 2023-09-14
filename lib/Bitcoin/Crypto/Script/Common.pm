package Bitcoin::Crypto::Script::Common;

use v5.10;
use strict;
use warnings;

use Type::Params -sigs;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Types qw(Str ByteStr InstanceOf);
use Bitcoin::Crypto::Exception;

sub _make_PKH
{
	my ($class, $script, $hash) = @_;

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

	return $script
		->add('OP_HASH160')
		->push($hash)
		->add('OP_EQUAL');
}

sub _make_WSH
{
	my ($class, $script, $hash) = @_;

	return $script
		->add('OP_SHA256')
		->push($hash)
		->add('OP_EQUAL');
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

	return $class->fill($type, btc_script->new, $data);
}

signature_for fill => (
	method => Str,
	positional => [Str, InstanceOf ['Bitcoin::Crypto::Script'], ByteStr],
);

sub fill
{
	my ($class, $type, $script, $data) = @_;

	my $method = $class->_get_method($type);
	return $class->$method($script, $data);
}

1;

