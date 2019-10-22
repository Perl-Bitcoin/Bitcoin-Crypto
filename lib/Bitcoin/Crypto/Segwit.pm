package Bitcoin::Crypto::Segwit;

use Modern::Perl "2010";
use Exporter qw(import);

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Config;

our @EXPORT_OK = qw(
	validate_program
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

our %segwit_validators = (
	0 => sub {
		my ($data) = @_;

		Bitcoin::Crypto::Exception->raise(
			code => "segwit_program",
			message => "incorrect witness program length"
		) unless length $data == 20 || length $data == 32;
		return;
	},
);

sub common_validator
{
	my ($data) = @_;

	Bitcoin::Crypto::Exception->raise(
		code => "segwit_program",
		message => "incorrect witness program length"
	) unless length $data >= 2 && length $data <= 40;
	return;
}

sub validate_program
{
	my ($program) = @_;

	my $version = unpack "C", $program;
	Bitcoin::Crypto::Exception->raise(
		code => "segwit_program",
		message => "incorrect witness program version $version"
	) unless defined $version && $version >= 0 && $version <= $config{max_witness_version};

	$program = substr $program, 1;
	my $validator = $segwit_validators{$version};
	common_validator($program);
	if (defined $validator && ref $validator eq ref sub{}) {
		$validator->($program);
	} else {
		Bitcoin::Crypto::Exception->warn(
			code => "segwit_program",
			message => "No validator for segwit program version $version is declared"
		);
	}

	return $version;
}

1;
