use v5.10;
use strict;
use warnings;
use Bitcoin::Crypto qw(btc_extprv btc_pub);

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
		signature => unpack("H*", $signature),
		public_key => $public->to_hex,
	};
}

sub verify
{
	my ($signature_hash) = @_;

	# re-create public key from hexadecimal data
	my $public = btc_pub->from_hex($signature_hash->{public_key});

	# get a bytestring signature from hexadecimal
	my $signature_bytes = pack "H*", $signature_hash->{signature};

	# perform a verification againts the public key
	return $public->verify_message(
		$signature_hash->{message},
		$signature_bytes,
		$signature_hash->{algorithm}
	);
}

# create a private key instance
my $mnemonic =
	"bachelor taxi wrong egg range weasel submit bless clutch liberty hip cloth guitar debate vibrant";
my $private = btc_extprv->from_mnemonic($mnemonic)->derive_key("m/0'")->get_basic_key;

my $signed_data = sign_message($private, "A quick brown fox jumped over a lazy dog");
if (verify $signed_data) {
	say 'verification ok';
}

$signed_data->{message} = "I've been hijacked!";
if (!verify $signed_data) {
	say 'verification ok';
}

__END__

=head1 Message signing script example

This example shows how to build a solution that will allow proving ownership of a private key. I<sign_message> function produces a hashref containing all the data required to verify you own a bitcoin address or a public key (bitcoin address is deterministically generated from a public key so they are pretty much the same thing), ready to be serialized using JSON for example. I<verify> function accepts this hashref and returns a true or false value, meaning whether the message is verified successfully.

