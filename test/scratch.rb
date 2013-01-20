# encoding: US-ASCII
require 'krypt'
require_relative 'resources'
require 'openssl'
require 'stringio'
require 'pp'

decoder = Krypt::ASN1

stringio = StringIO.new(
[
  Krypt::ASN1::Null.new,
  Krypt::ASN1::Integer.new(0)
].map { |e| e.to_der }.join
)
c = Class.new do
  def initialize(io)
    @io = io
  end

  def read(*args)
    @io.read(*args)
  end
end

generic = c.new(stringio)
p decoder.decode_der(generic)
p decoder.decode_der(generic)
