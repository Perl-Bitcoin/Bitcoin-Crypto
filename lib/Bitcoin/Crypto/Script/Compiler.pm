package Bitcoin::Crypto::Script::Compiler;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;

use Try::Tiny;
use Scalar::Util qw(blessed);
use List::Util qw(sum0);

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(die_no_trace);

has param 'script' => (
	coerce => BitcoinScript,
	weak_ref => 1,
);

has field 'operations' => (
	isa => ArrayRef [ArrayRef],
	writer => -hidden,
);

has field 'unconditionally_valid' => (
	isa => Bool,
	writer => -hidden,
);

has field 'errors' => (
	default => sub { [] },
);

has field 'opcode_count' => (
	isa => PositiveOrZeroInt,
	writer => -hidden,
);

sub has_errors
{
	my ($self) = @_;

	return @{$self->errors} > 0;
}

sub assert_correct
{
	my ($self) = @_;

	return if $self->unconditionally_valid;
	return unless $self->has_errors;

	# show just the first error
	die $self->errors->[0];
}

sub compile
{
	my ($self) = @_;
	my $script = $self->script;
	my $opcode_class = $script->opcode_class;
	my @ops;
	my @debug_ops;

	my $raw_script = $script->to_serialized;
	my %context = (
		serialized => $raw_script,
		position => 0,
		offset => 0,
		size => length $raw_script,
	);

	while ($context{offset} < $context{size}) {
		try {
			my $this_byte = substr $context{serialized}, $context{offset}++, 1;
			my $opcode;
			my @to_push;

			$opcode = $opcode_class->get_opcode_by_code(ord $this_byte);
			push @to_push, $this_byte;

			push @debug_ops, $opcode->name;
			unshift @to_push, $opcode;

			push @ops, \@to_push;

			if ($opcode->has_on_compilation) {
				$opcode->on_compilation->($self, \@to_push, \%context);
			}

			$context{position}++;
		}
		catch {
			my $ex = $_;

			if (blessed $ex && $ex->isa('Bitcoin::Crypto::Exception::ScriptCompilation')) {
				$ex->set_script(\@debug_ops);
				$ex->set_error_position($context{position});
				push @{$self->errors}, $ex;
				$context{position}++;
			}
			else {
				die $ex;
			}
		};
	}

	push @{$self->errors},
		Bitcoin::Crypto::Exception::ScriptCompilation->new(message => 'not enough bytes of data in the script')
		unless $context{offset} == $context{size};

	push @{$self->errors}, Bitcoin::Crypto::Exception::ScriptCompilation->new(message => 'some OP_IFs were not closed')
		if $context{branch};

	$self->_set_opcode_count(sum0 map { $_->[0]->non_push_opcode } @ops);
	$self->_set_operations(\@ops);
	return $self;
}

sub _compile_data_push
{
	my ($self, $context, $size) = @_;

	$self->_invalid_script(
		'no PUSHDATA size in the script'
	) unless defined $size;

	# we may go past the script end - that's okay
	$context->{offset} += $size;

	return substr $context->{serialized}, $context->{offset} - $size, $size;
}

sub _invalid_script
{
	my ($self, $error) = @_;

	Bitcoin::Crypto::Exception::ScriptCompilation->raise($error);
}

sub _unconditionally_valid_script
{
	my ($self, $error) = @_;

	$self->_set_unconditionally_valid(!!1);
}

1;

