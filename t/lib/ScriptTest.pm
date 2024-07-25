package ScriptTest;

use Test2::V0;

use Exporter qw(import);

use Bitcoin::Crypto::Script::Runner;

our @EXPORT = qw(
	script_fill
	stack_is
	ops_are
);

sub script_fill
{
	my $script = shift;
	foreach my $op (@_) {
		if ($op =~ m/^OP_/) {
			$script->add($op);
		}
		else {
			$script->push(pack 'H*', $op);

			# hack opcode back into the caller to pass in 'ops_are'
			$op = 'OP_PUSHDATA1';
		}
	}
}

sub stack_is
{
	my ($script, $stack_aref, $message) = @_;
	$message //= 'script executed stack ok';

	$stack_aref = [map { unpack 'H*', $_ } @$stack_aref];

	if (ref $script eq 'CODE') {
		$script = $script->();
	}

	my $out_stack;
	if ($script->isa('Bitcoin::Crypto::Script')) {
		$out_stack = [map { unpack 'H*', $_ } @{$script->run->stack}];
	}
	elsif ($script->isa('Bitcoin::Crypto::Script::Runner')) {
		$out_stack = [map { unpack 'H*', $_ } @{$script->stack}];
	}
	else {
		die 'invalid argument to stack_is';
	}

	is $out_stack, $stack_aref, $message;
}

sub ops_are
{
	my ($script, $ops_aref, $message) = @_;
	$message //= 'script ops ok';

	my $out_ops = [map { $_->[0]->name } @{$script->operations}];
	is $out_ops, $ops_aref, $message;
}

1;

