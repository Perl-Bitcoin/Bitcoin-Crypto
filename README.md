# Bitcoin::Crypto
A Perl module for performing Bitcoin cryptographic operations.

## Code and documentation
[Bitcoin::Crypto on CPAN](https://metacpan.org/release/Bitcoin-Crypto)

## Bugs and feature requests
Please use the Github's issue tracker to file both bugs and feature requests.

## Contributions
Contributions to the project in form of Github's pull requests are
welcome. Please make sure your code is in line with the general
coding style of the module. Let me know if you plan something
bigger so we can talk it through.

## Release testing
This module includes some large tests which are only used for release testing.
To run these tests, `prove -l -r xt/release` command can be executed. To run
them with built distribution, `RELEASE_TESTS_DATA` environmental variable must
be set, since large data files for these tests are not included.
`LONG_RELEASE_TESTS` environmental variable can be set to run tests which are
known for very slow execution.

Releasing Bitcoin::Crypto should be done as follows:

```sh
RELEASE_TESTS_DATA=$PWD/xt/data dzil release
```

### Author
Bartosz Jarzyna <bbrtj.pro@gmail.com>

