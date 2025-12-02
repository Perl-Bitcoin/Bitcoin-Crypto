package Bitcoin::Crypto::Transaction::Signer::P2PKH;

use v5.10;
use strict;
use warnings;

use Mooish::Base -standard;

use Bitcoin::Crypto qw(btc_script);
use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

extends 'Bitcoin::Crypto::Transaction::Signer::CustomLegacy';
with 'Bitcoin::Crypto::Transaction::Signer::Role::KeyHash';

1;

