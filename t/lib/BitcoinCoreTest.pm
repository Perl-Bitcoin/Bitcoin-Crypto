package BitcoinCoreTest;

use v5.14;
use warnings;

use Test2::V0;

use Bitcoin::Crypto qw(btc_script btc_tapscript);
use Bitcoin::Crypto::Transaction::Flags;

use Exporter qw(import);
our @EXPORT = qw(
	get_flags
	get_file_data
	script_from_readable
);

BEGIN {
	eval { require JSON::MaybeXS; 1 }
		or skip_all 'This test requires module JSON::MaybeXS';

	JSON::MaybeXS->import(qw(decode_json));
}

# returns consensus flags object. With reverse arguments, returns consensus
# without given flags
sub get_flags
{
	my ($string, $reverse) = @_;
	$reverse //= !!0;

	state $core_to_perl = {
		P2SH => 'p2sh',
		DERSIG => 'der_signatures',
		CHECKLOCKTIMEVERIFY => 'checklocktimeverify',
		CHECKSEQUENCEVERIFY => 'checksequenceverify',
		NULLDUMMY => 'null_dummy',
		WITNESS => 'segwit',
		TAPROOT => 'taproot',

		CONST_SCRIPTCODE => 'const_script',
		LOW_S => 'low_s_signatures',
		STRICTENC => 'strict_encoding',
		MINIMALIF => 'minimal_if',
		NULLFAIL => 'null_fail',
		SIGPUSHONLY => 'signature_pushes_only',
		MINIMALDATA => 'minimal_data',
		CLEANSTACK => 'clean_stack',
		DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM => 'known_witness',
		WITNESS_PUBKEYTYPE => 'compressed_pubkeys',
		DISCOURAGE_UPGRADABLE_NOPS => 'illegal_upgradeable_nops',
	};

	my %flags = map { $core_to_perl->{$_} => !$reverse }
		grep { defined $core_to_perl->{$_} }
		split /,/, $string;

	my $method = $reverse ? 'new_full' : 'new_empty';
	return Bitcoin::Crypto::Transaction::Flags->$method(%flags);
}

sub get_file_data
{
	my ($case_name) = @_;

	local $/;

	my $file_location = $ENV{RELEASE_TESTS_DATA}
		or die 'no RELEASE_TESTS_DATA environmental variable was specified';

	my $file = "$file_location/$case_name.json";
	open my $fh, '<', $file
		or die "$case_name test requires file $file";

	return decode_json(readline $fh);
}

sub script_from_readable
{
	my ($readable_string, $tapscript) = @_;
	$tapscript //= !!0;

	my $script = $tapscript ? btc_tapscript->new : btc_script->new;
	my @parts = grep { length } split /\s+/, $readable_string;

	foreach my $part (@parts) {
		if ($part =~ m/^-?[0-9]+$/) {
			$script->push_number($part);
		}
		elsif ($part =~ m/^0x([0-9a-f]+)$/i) {
			$script->add_raw([hex => $1]);
		}
		elsif ($part =~ m/^'([^']*)'$/) {
			$script->push_bytes($1 // '');
		}
		else {
			$part =~ s/^OP_//;
			$script->add("OP_$part");
		}
	}

	return $script;
}

1;

