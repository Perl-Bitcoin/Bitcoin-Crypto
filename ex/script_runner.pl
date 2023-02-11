use v5.10;
use strict;
use warnings;

use Data::Dumper;
$Data::Dumper::Terse = 'stack';

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Script::Runner;

sub print_stack
{
	my ($runner) = @_;

	print 'stack: ';
	say Dumper(
		[
			map {
				to_format [hex => $_]
			} @{$runner->stack}
		]
	);
}

say 'please provide a serialized bitcoin script (hexadecimal):';
my $script_hex = <STDIN>;
chomp $script_hex;

my $runner = Bitcoin::Crypto::Script::Runner->new;
my $script = btc_script->from_serialized([hex => $script_hex]);
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

