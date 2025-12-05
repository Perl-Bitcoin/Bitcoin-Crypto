package Bitcoin::Crypto::Util::Internal;

use v5.14;
use warnings;

use Exporter qw(import);
use Unicode::Normalize;
use Crypt::KeyDerivation qw(pbkdf2);
use Encode qw(encode);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::Digest::SHA256 qw(sha256);
use Bitcoin::BIP39 qw(gen_bip39_mnemonic entropy_to_bip39_mnemonic);
use Feature::Compat::Try;
use Scalar::Util qw(blessed);
use Types::Common -types, -sigs;

use Bitcoin::Crypto::Helpers qw(parse_formatdesc ecc);
use Bitcoin::Crypto::Constants qw(:key :witness);
use Bitcoin::Crypto::Types -types;
use Bitcoin::Crypto::Exception;

our @EXPORT_OK = qw(
	validate_wif
	validate_segwit
	get_address_type
	get_key_type
	get_public_key_compressed
	generate_mnemonic
	mnemonic_from_entropy
	mnemonic_to_seed
	get_path_info
	from_format
	to_format
	pack_compactsize
	unpack_compactsize
	hash160
	hash256
	merkle_root
	tagged_hash
	lift_x
	has_even_y
	get_taproot_ext
);

our %EXPORT_TAGS = (all => [@EXPORT_OK]);

sub validate_wif
{
	my ($wif) = @_;

	require Bitcoin::Crypto::Base58;
	my $byte_wif = Bitcoin::Crypto::Base58::decode_base58check($wif);

	my $last_byte = substr $byte_wif, -1;
	if (length $byte_wif == KEY_MAX_LENGTH + 2) {
		return $last_byte eq WIF_COMPRESSED_BYTE;
	}
	else {
		return length $byte_wif == KEY_MAX_LENGTH + 1;
	}
}

sub validate_segwit
{
	my ($program) = @_;

	my $version = unpack 'C', $program;
	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		'incorrect witness program version ' . ($version // '[null]')
	) unless defined $version && $version >= 0 && $version <= MAX_WITNESS_VERSION;

	$program = substr $program, 1;

	# common validator
	Bitcoin::Crypto::Exception::SegwitProgram->raise(
		'incorrect witness program length'
	) unless length $program >= 2 && length $program <= 40;

	if ($version == 0) {

		# SegWit validator
		Bitcoin::Crypto::Exception::SegwitProgram->raise(
			'incorrect witness program length (segwit)'
		) unless length $program == 20 || length $program == 32;
	}
	elsif ($version == 1) {

		# Taproot validator

		# taproot outputs are 32 bytes, but other lengths "remain unencumbered"
		# do not throw this exception to make bip350 test suite pass (10-Bech32.t)

		# Bitcoin::Crypto::Exception::SegwitProgram->raise(
		# 	'incorrect witness program length (taproot)'
		# ) unless length $program == 32;
	}

	return $version;
}

sub get_address_type
{
	my ($address, $network_id) = @_;

	require Bitcoin::Crypto::Base58;
	require Bitcoin::Crypto::Bech32;
	require Bitcoin::Crypto::Network;

	my $network = Bitcoin::Crypto::Network->get($network_id // ());
	my $type;

	# first, try segwit
	if ($network->supports_segwit) {
		try {
			Bitcoin::Crypto::Exception::SegwitProgram->raise(
				'invalid human readable part in address'
			) unless Bitcoin::Crypto::Bech32::get_hrp($address) eq $network->segwit_hrp;

			my $data = Bitcoin::Crypto::Bech32::decode_segwit($address);
			my $version = ord substr $data, 0, 1, '';

			$type = 'P2TR'
				if $version == TAPROOT_WITNESS_VERSION
				&& length $data == 32;

			return $type if $type;

			Bitcoin::Crypto::Exception::SegwitProgram->raise(
				"invalid segwit address of version $version"
			) unless $version == SEGWIT_WITNESS_VERSION;

			$type = 'P2WPKH' if length $data == 20;
			$type = 'P2WSH' if length $data == 32;

			return $type if $type;

			Bitcoin::Crypto::Exception::Address->raise(
				'invalid segwit address'
			);
		}
		catch ($ex) {
			die $ex unless blessed $ex && $ex->isa('Bitcoin::Crypto::Exception::Bech32InputFormat');
		}
	}

	# then, try legacy
	try {
		my $data = Bitcoin::Crypto::Base58::decode_base58check($address);
		my $byte = substr $data, 0, 1, '';

		$type = 'P2PKH' if $byte eq $network->p2pkh_byte;
		$type = 'P2SH' if $byte eq $network->p2sh_byte;

		Bitcoin::Crypto::Exception::Address->raise(
			'invalid legacy address'
		) unless length $data == 20;

		return $type if $type;

		Bitcoin::Crypto::Exception::Address->raise(
			'invalid first byte in address'
		);
	}
	catch ($ex) {
		die $ex unless blessed $ex && $ex->isa('Bitcoin::Crypto::Exception::Base58InputFormat');
	};

	Bitcoin::Crypto::Exception::Address->raise(
		"not an address: $address"
	);
}

sub get_key_type
{
	my $entropy = shift;

	return 0 if defined get_public_key_compressed($entropy);
	return 1
		if length $entropy <= KEY_MAX_LENGTH;
	return undef;
}

sub get_public_key_compressed
{
	my $entropy = shift;
	my $octet = unpack 'C', $entropy;

	return undef unless defined $octet;

	if ($octet == 0x02 || $octet == 0x03) {
		return 1 if length $entropy == KEY_MAX_LENGTH + 1;
	}
	elsif ($octet == 0x04 || $octet == 0x06 || $octet == 0x07) {
		return 0 if length $entropy == 2 * KEY_MAX_LENGTH + 1;
	}

	return undef;
}

sub mnemonic_to_seed
{
	my ($mnemonic, $password) = @_;

	$mnemonic = encode('UTF-8', NFKD($mnemonic));
	$password = encode('UTF-8', NFKD('mnemonic' . ($password // '')));

	return pbkdf2($mnemonic, $password, 2048, 'SHA512', 64);
}

sub generate_mnemonic
{
	my ($len, $lang) = @_;
	my ($min_len, $len_div, $max_len) = (128, 32, 256);

	# bip39 specification values
	Bitcoin::Crypto::Exception::MnemonicGenerate->raise(
		"required entropy of between $min_len and $max_len bits, divisible by $len_div"
	) if $len < $min_len || $len > $max_len || $len % $len_div != 0;

	return Bitcoin::Crypto::Exception::MnemonicGenerate->trap_into(
		sub {
			my $ret = gen_bip39_mnemonic(bits => $len, language => $lang);
			$ret->{mnemonic};
		}
	);
}

sub mnemonic_from_entropy
{
	my ($entropy, $lang) = @_;

	return Bitcoin::Crypto::Exception::MnemonicGenerate->trap_into(
		sub {
			entropy_to_bip39_mnemonic(
				entropy => $entropy,
				language => $lang
			);
		}
	);
}

sub get_path_info
{
	my ($path) = @_;

	# NOTE: ->coerce may still throw because of exceptions in from_string of DerivationPath
	try {
		return scalar DerivationPath->assert_coerce($path);
	}
	catch ($e) {
		return undef;
	}
}

sub from_format ($)
{
	state $sig = signature(positional => [Tuple [FormatStr, Str]]);
	my ($format, $data) = @{($sig->(@_))[0]};

	return parse_formatdesc($format, $data);
}

sub to_format ($)
{
	state $sig = signature(positional => [Tuple [FormatStr, ByteStr]]);
	my ($format, $data) = @{($sig->(@_))[0]};

	return parse_formatdesc($format, $data, 1);
}

sub pack_compactsize
{
	my $value = shift;

	if ($value <= 0xfc) {
		return pack 'C', $value;
	}
	elsif ($value <= 0xffff) {
		return pack 'Cv', 0xfd, $value;
	}
	elsif ($value <= 0xffffffff) {
		return pack 'CV', 0xfe, $value;
	}
	else {
		# 32 bit archs should not reach this
		return pack 'CVV', 0xff, $value & 0xffffffff, $value >> 32;
	}
}

sub unpack_compactsize
{
	my ($stream, $pos_ref) = @_;
	my $partial = !!$pos_ref;
	my $pos = $partial ? $$pos_ref : 0;

	# if the first byte is 0xfd, 0xfe or 0xff, then CompactSize contains 2, 4 or 8
	# bytes respectively
	my $value = ord substr $stream, $pos++, 1;
	if ($value > 0xfc) {
		my $length = 1 << ($value - 0xfc);

		Bitcoin::Crypto::Exception->raise(
			"cannot unpack CompactSize: not enough data in stream"
		) if length $stream < $length;

		if ($length == 2) {
			$value = unpack "\@$pos v", $stream;
		}
		elsif ($length == 4) {
			$value = unpack "\@$pos V", $stream;
		}
		else {
			Bitcoin::Crypto::Exception->raise(
				"cannot unpack CompactSize: no 64 bit support"
			) if !Bitcoin::Crypto::Constants::is_64bit;

			my ($lower, $higher) = unpack "\@$pos VV", $stream;
			$value = ($higher << 32) + $lower;
		}

		$pos += $length;
	}

	Bitcoin::Crypto::Exception->raise(
		"cannot unpack CompactSize: leftover data in stream"
	) if !$partial && $pos != length $stream;

	$$pos_ref = $pos
		if $partial;

	return $value;
}

sub hash160
{
	return ripemd160(sha256(shift));
}

sub hash256
{
	return sha256(sha256(shift));
}

sub merkle_root
{
	my ($leaves) = @_;

	my @parts = map { hash256($_) } @$leaves;

	Bitcoin::Crypto::Exception->raise(
		'need at least one element to calculate a merkle root'
	) unless @parts;

	while (@parts > 1) {
		@parts = map {
			hash256($parts[$_] . ($parts[$_ + 1] // $parts[$_]))
		} grep {
			$_ % 2 == 0
		} 0 .. $#parts;
	}

	return $parts[0];
}

sub tagged_hash
{
	my ($tag, $message) = @_;
	state $tags = {};

	$tags->{$tag} //= sha256(encode 'UTF-8', $tag) x 2;
	return sha256($tags->{$tag} . $message);
}

sub lift_x
{
	my ($x) = @_;

	my $key = "\x02" . ($x // '');
	Bitcoin::Crypto::Exception::KeyCreate->raise(
		'invalid xonly public key'
	) unless ecc->verify_public_key($key);

	return $key;
}

sub has_even_y
{
	my ($key) = @_;
	$key = $key->raw_key if ref $key;

	return Bitcoin::Crypto::Exception->trap_into(
		sub {
			$key = ecc->compress_public_key($key);
			return substr($key, 0, 1) eq "\x02";
		}
	);
}

sub get_taproot_ext
{
	my ($ext_flag, %args) = @_;

	if ($ext_flag == 0) {
		return '';
	}
	elsif ($ext_flag == 1) {
		state $type = Dict [
			script_tree => BitcoinScriptTree,
			leaf_id => Int,
			codesep_pos => Optional [Maybe [PositiveOrZeroInt]],
		];

		$type->assert_valid(\%args);

		# https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension
		return $args{script_tree}->get_tapleaf_hash($args{leaf_id})
			. pack('xV', $args{codesep_pos} // 0xffffffff);
	}
	else {
		Bitcoin::Crypto::Exception->raise(
			"can not create taproot_ext for unknown ext flag $ext_flag"
		);
	}
}

1;

