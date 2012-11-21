=begin

= Info

krypt - Modern platform- and library-independent cryptography for Ruby 

Copyright (C) 2011, 2012
Hiroshi Nakamura <nahi@ruby-lang.org>
Martin Bosslet <martin.bosslet@googlemail.com>
All rights reserved.

= License
This program is distributed under the same license as Ruby.
See the file 'LICENSE' for further details.

=end

require_relative 'krypt_missing'
require_relative 'krypt/provider'

require 'krypt-core'

# The following files depend on krypt-core being loaded
require_relative 'krypt/asn1'
require_relative 'krypt/x509'
require_relative 'krypt/codec'

