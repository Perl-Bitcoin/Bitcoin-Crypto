package Bitcoin::Crypto::Types;

use Modern::Perl '2010';
use Exporter qw(import);
use MooX::Types::MooseLike;

our @EXPORT_OK;

MooX::Types::MooseLike::register_types([{
  name => "IntMaxBits",
  test => sub { $_[0] =~ /^\d+$/ && $_[0] >= 0 && $_[0] < (2 << $_[1] - 1) },
  message => sub { "Value $_[0] is not in between 0 and " . ((2 << $_[1] - 1) - 1) },
}], __PACKAGE__);

MooX::Types::MooseLike::register_types([{
  name => "StrExactLength",
  test => sub { length $_[0] == $_[1] },
  message => sub { "String's length is not equal $_[1]" },
}], __PACKAGE__);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

1;
