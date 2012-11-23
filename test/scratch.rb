require 'krypt'
require_relative 'resources'
require 'openssl'
require 'stringio'
require 'pp'

class MyDigest
  def initialize(alg)
    @alg = alg
  end

  def digest
    puts @alg
  end
end

class MyProvider
  def new_service(klass, *rest)
    if klass == Krypt::Digest
      return MyDigest.new(rest[0])
    end
    nil
  end
end

Krypt::Provider.register(:my, MyProvider.new)

d = Krypt::Digest.new("SHA1")
d2 = Krypt::Digest::SHA256.new

d.digest
d2.digest
