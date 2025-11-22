package Bitcoin::Crypto::Transaction::Signer::P2SH;

use v5.10;
use strict;
use warnings;

use Moo;
use Mooish::AttributeBuilder -standard;
use Types::Common -types, -sigs;

use Bitcoin::Crypto::Exception;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Types -types;

use namespace::clean;

extends 'Bitcoin::Crypto::Transaction::Signer::Legacy';
with 'Bitcoin::Crypto::Transaction::Signer::Role::ScriptHash';

1;

