use v5.10;
use strict;
use warnings;

use Data::Dumper;
$Data::Dumper::Terse = 'stack';

use Bitcoin::Crypto::Script;
use Bitcoin::Crypto::Script::Runner;

sub print_stack
{
	my ($runner) = @_;

	print 'stack: ';
	say Dumper(
		[
			map {
				unpack 'H*', $_
			} @{$runner->stack}
		]
	);
}

say 'please provide a serialized bitcoin script (hexadecimal):';
my $script_hex = <STDIN>;
chomp $script_hex;

my $runner = Bitcoin::Crypto::Script::Runner->new;
my $script = Bitcoin::Crypto::Script->from_serialized_hex($script_hex);
$runner->start($script);

say 'starting the runtime...';
say '-------------';

while (1) {
	my $pos = $runner->pos;
	last unless $runner->step;
	say 'executed opcode ' . $runner->operations->[$pos][0]->name;
	print_stack($runner);
	say '-------------';
}

say 'finished!';
print_stack($runner);

__END__

=head1 Script runner example

This example runs a script, passed in hex form, one step at a time. After each
step the script stack is printed.

