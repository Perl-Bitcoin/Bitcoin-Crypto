use Test2::V0;
use Bitcoin::Crypto qw(btc_psbt);

my @cases = (
	[
		'PSBT_IN_TAP_INTERNAL_KEY key that is too long (incorrectly serialized as compressed DER)',
		qr{invalid xonly public key},
		'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXARchAv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyAAAA'
	],

	[
		'PSBT_KEY_PATH_SIG signature that is too short',
		qr{invalid signature length},
		'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXARM/Fzuz02wHSvtxb+xjB6BpouRQuZXzyCeFlFq43w4kJg3NcDsMvzTeOZGEqUgawrNYbbZgHwJqd/fkk4SBvDR1AAAA'
	],

	[
		'PSBT_KEY_PATH_SIG signature that is too long',
		qr{invalid signature length},
		'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXARNCFzuz02wHSvtxb+xjB6BpouRQuZXzyCeFlFq43w4kJg3NcDsMvzTeOZGEqUgawrNYbbZgHwJqd/fkk4SBvDR1FwGqAAAA'
	],

	[
		'PSBT_IN_TAP_BIP32_DERIVATION key that is too long (incorrectly serialized as compressed DER)',
		qr{invalid xonly public key},
		'cHNidP8BAHECAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Anh8AQAAAAAAFgAUg6fjS9mf8DpJYu+KGhAbspVGHs5gawQqAQAAABYAFHrDad8bIOAz1hFmI5V7CsSfPFLoAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXIhYC/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIZAHcrLadWAACAAQAAgAAAAIABAAAAAAAAAAAAAA=='
	],

	[
		'PSBT_OUT_TAP_INTERNAL_KEY key that is too long (incorrectly serialized as compressed DER)',
		qr{invalid xonly public key},
		'cHNidP8BAH0CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Aoh7AQAAAAAAFgAUI4KHHH6EIaAAk/dU2RKB5nWHS59gawQqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAABBSEC/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIA'
	],

	[
		'PSBT_OUT_TAP_BIP32_DERIVATION key that is too long (incorrectly serialized as compressed DER)',
		qr{invalid xonly public key},
		'cHNidP8BAH0CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////Aoh7AQAAAAAAFgAUI4KHHH6EIaAAk/dU2RKB5nWHS59gawQqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAAAAAABASsA8gUqAQAAACJRIFosLPW1LPMfg60ujaY/8DGD7Nj2CcdRCuikjgORCgdXAAAiBwL+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMhkAdystp1YAAIABAACAAAAAgAEAAAAAAAAAAA=='
	],

	[
		'PSBT_IN_TAP_SCRIPT_SIG key that is too long (incorrectly serialized as compressed DER)',
		qr{invalid length},
		'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJCFAIssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20s2XDhX1P8DIL5UP1WD/qRm3YXK+AXNoqJkTrwdPQAsJQIl1aqNznMxonsD886NgvjLMC1mxbpOh6LtGBXJrLKej/3BsQXZkljKyzGjh+RK4pXjjcZzncQiFx6lm9JvNQ8sAAA=='
	],

	[
		'PSBT_IN_TAP_SCRIPT_SIG signature that is too long',
		qr{invalid signature length},
		'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJBFCyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwlCiXVqo3OczGiewPzzo2C+MswLWbFuk6Hou0YFcmssp6P/cGxBdmSWMrLMaOH5ErileONxnOdxCIXHqWb0m81DywEBAAA='
	],

	[
		'PSBT_IN_TAP_SCRIPT_SIG signature that is too short',
		qr{invalid signature length},
		'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJBFCyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwk/iXVqo3OczGiewPzzo2C+MswLWbFuk6Hou0YFcmssp6P/cGxBdmSWMrLMaOH5ErileONxnOdxCIXHqWb0m81DAAA='
	],

	[
		'PSBT_IN_TAP_LEAF_SCRIPT Control block that is too long',
		qr{did not pass type constraint \Q"ArrayRef[ByteStrLen[32]]"\E},
		'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJjFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgAIyAssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20qzAAAA='
	],

	[
		'PSBT_IN_TAP_LEAF_SCRIPT Control block that is too short',
		qr{did not pass type constraint \Q"ArrayRef[ByteStrLen[32]]"\E},
		'cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgAw2k/OT32yjCyylRYx4ANxOFZZf+ljiCy1AOaBEsymMAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJhFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4SMgLLE6xoJI3oBqpqNlnPPAPraCHQnIEUpOho/r3oZbttKswAAA'
	],
);

foreach my $error_case (@cases) {
	my ($name, $err, $base64) = @{$error_case};

	subtest "testing case $name" => sub {
		my $caught = dies {
			btc_psbt->from_serialized([base64 => $base64]);
		};

		like $caught, $err, 'error ok';
		isa_ok $caught, 'Bitcoin::Crypto::Exception::PSBT';
	};
}

done_testing;

