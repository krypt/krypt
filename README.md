<p align="center">
  <img src="http://emboss.github.com/images/krypt-logo.png" alt="krypt" />
</p>

=========
[![Build Status](https://secure.travis-ci.org/krypt/krypt.png)](http://travis-ci.org/krypt/krypt)


krypt. semper pi.
-----------------

The goal of krypt is to provide a platform- and
library-independent cryptography API for the Ruby
language (http://www.ruby-lang.org). It can be used
with all C(++)-based Ruby implementations as well as
JRuby.

The major part of krypt is implemented in Ruby, and it 
additionally offers the possibility to integrate OS- 
or language-specific native libraries to implement
cryptographic primitives. krypt aims at offering 
performance while still improving the security and
features of the Ruby cryptography infrastructure. Its 
motto is to keep all the good parts of what exists 
today and to improve the parts that need improvement.
It offers an idiomatic, modern API that cherry-picks
the best features of other popular libraries and also
offers new features that are not offered by others today.


krypt-core-c
------------

The C implementation of the krypt-core API to be used
with all C-based Rubies. The repository can be found at

https://github.com/krypt/krypt-core-c.

krypt-core-java
---------------

Realizes the krypt-core API in Java to be used by Jruby 
(http://www.jruby.org). The repository can be found at 

https://github.com/krypt/krypt-core-java.

krypt-core-ruby
---------------

An all Ruby implementation of krypt-core. Access to
the native krypt-provider libraries is realized via FFI.
The repository can be found at

https://github.com/krypt/krypt-core-ruby.

krypt-provider-openssl
----------------------

A realization of the krypt-provider API in C that
utilizes OpenSSL (http://www.openssl.org). Can also be used
by JRuby via krypt-core-ruby and FFI. The repository
is at

https://github.com/krypt/krypt-provider-openssl.

krypt-provider-jdk
------------------

Realization of the krypt-provider API in Java exclusively
to be used by JRuby. The implementation is based on the
JDK built-in security and cryptography library. The
repository is at

https://github.com/krypt/krypt-provider-jdk.

