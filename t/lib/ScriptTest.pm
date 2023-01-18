package ScriptTest;

use v5.10;
use strict;
use warnings;

use Exporter qw(import);
use Test::More;

use Bitcoin::Crypto::Script::Runner;

our @EXPORT = qw(
	stack_is
	ops_are
);

sub stack_is
{
	my ($script, $stack_aref, $message) = @_;
	$message //= 'script executed stack ok';

	$stack_aref = [map { unpack 'H*', $_ } @$stack_aref];

	my $out_stack;
	if ($script->isa('Bitcoin::Crypto::Script')) {
		$out_stack = [map { unpack 'H*', $_ } @{$script->run}];
	}
	elsif ($script->isa('Bitcoin::Crypto::Script::Runner')) {
		$out_stack = [map { unpack 'H*', $_ } @{$script->stack}];
	}
	else {
		die 'invalid argument to stack_is';
	}

	is_deeply $out_stack, $stack_aref, $message;
}

sub ops_are
{
	my ($script, $ops_aref, $message) = @_;
	$message //= 'script ops ok';

	my $out_ops = [map { $_->[0]->name } @{$script->operations}];
	is_deeply $out_ops, $ops_aref, $message;
}

1;

