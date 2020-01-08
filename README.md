# Bitcoin::Crypto - cryptographic perl package for Bitcoin

This module aims at enabling easy manipulation of Bitcoin keypairs, signatures, addresses and networks. It contains, among other things, representation classes for private and public keys, network management module and Bitcoin-compatible Base58 and bech32 implementations.

## INSTALLATION

To install from cpan, type:

	cpanm Bitcoin::Crypto

To install this module manually, following can be used:

	perl Makefile.PL
	make
	make test
	make install

## DEPENDENCIES

This module requires other modules to function, which are listed in Makefile.PL.
These modules can be installed by running for example:
	cpanm --installdeps .
This module also requires development GMP package installed on your system.
It must be installed before installing other dependencies.

For the best performance during dependencies installation ensure that you have Math::BigInt::GMP package installed. Some of the dependencies can run their test suites orders of magnitude faster with GMP available.

## COPYRIGHT AND LICENCE

Copyright (C) 2018 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

