package Bitcoin::Crypto::Script::Compiler;

use v5.14;
use warnings;

use Mooish::Base -standard;

use Feature::Compat::Try;
use Scalar::Util qw(blessed);

use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Helpers qw(die_no_trace);
use Bitcoin::Crypto::Script::Compiler::Opcode;

has param 'operations' => (
	isa => ArrayRef [ArrayRef],
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
	my $self = shift;

	return @{$self->errors} > 0;
}

sub assert_valid
{
	my $self = shift;

	return if $self->unconditionally_valid;
	return unless $self->has_errors;

	# show just the first error
	die $self->errors->[0];
}

sub compile
{
	my ($class, $script) = @_;
	my $opcode_class = $script->opcode_class;
	my @ops;
	my $non_push_opcodes = 0;
	my @debug_ops;

	my $self = $class->new(
		operations => \@ops
	);

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

			my $opcode = $opcode_class->get_opcode_by_code(ord $this_byte);
			push @debug_ops, $opcode->name;
			my $compiled_op = Bitcoin::Crypto::Script::Compiler::Opcode->new($opcode, $this_byte);

			push @ops, $compiled_op;
			$non_push_opcodes++ if $opcode->non_push_opcode;

			if ($opcode->has_on_compilation) {
				$opcode->on_compilation->($self, $compiled_op, \%context);
			}

			$context{position}++;
		}
		catch ($ex) {
			if (blessed $ex && $ex->isa('Bitcoin::Crypto::Exception::ScriptCompilation')) {
				$ex->set_script(\@debug_ops);
				$ex->set_error_position($context{position});
				push @{$self->errors}, $ex;
				$context{position}++;
			}
			else {
				die $ex;
			}
		}
	}

	push @{$self->errors},
		Bitcoin::Crypto::Exception::ScriptCompilation->new(message => 'not enough bytes of data in the script')
		unless $context{offset} == $context{size};

	push @{$self->errors},
		Bitcoin::Crypto::Exception::ScriptCompilation->new(message => 'some OP_IFs were not closed')
		if $context{branch};

	$self->_set_opcode_count($non_push_opcodes);
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

