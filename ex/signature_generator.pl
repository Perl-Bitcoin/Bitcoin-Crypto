use v5.10;
use strict;
use warnings;
use Bitcoin::Crypto qw(btc_extprv btc_pub);
use Bitcoin::Crypto::Util qw(to_format);

sub sign_message
{
	my ($private, $message, $algo) = @_;

	# algo needs to be available in Digest:: namespace
	$algo //= "sha256";

	die "key is not a private key instance"
		unless $private->isa("Bitcoin::Crypto::Key::Private");

	# sign message and produce a public key, which will be needed
	# in verification
	my $signature = $private->sign_message($message, $algo);
	my $public = $private->get_public_key;

	# complete data needed to prove ownership of a private key
	# ready to be serialized
	return {
		message => $message,
		algorithm => $algo,
		signature => to_format [hex => $signature],
		public_key => to_format [hex => $public->to_serialized],
	};
}

sub verify_message
{
	my ($signature_hash) = @_;

	# re-create public key from hexadecimal data
	my $public = btc_pub->from_serialized([hex => $signature_hash->{public_key}]);

	# perform a verification againts the public key
	return $public->verify_message(
		$signature_hash->{message},
		[hex => $signature_hash->{signature}],
		$signature_hash->{algorithm}
	);
}

# create a private key instance
my $mnemonic =
	"bachelor taxi wrong egg range weasel submit bless clutch liberty hip cloth guitar debate vibrant";
my $private = btc_extprv->from_mnemonic($mnemonic)->derive_key("m/0'")->get_basic_key;

my $signed_data = sign_message($private, "A quick brown fox jumped over a lazy dog");
if (verify_message $signed_data) {
	say 'verification ok';
}

$signed_data->{message} = "I've been hijacked!";
if (!verify_message $signed_data) {
	say 'verification ok';
}

__END__

=head1 Message signing script example

This example shows how to build a solution that will allow proving ownership of a private key. I<sign_message> function produces a hashref containing all the data required to verify you own a bitcoin address or a public key (bitcoin address is deterministically generated from a public key so they are pretty much the same thing), ready to be serialized using JSON for example. I<verify> function accepts this hashref and returns a true or false value, meaning whether the message is verified successfully.

