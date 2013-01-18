# encoding: US-ASCII
require 'krypt'
require_relative 'resources'
require 'openssl'
require 'stringio'
require 'pp'

def _B(bin_encode)
  [bin_encode.reverse].pack('b*').reverse
end

value = _B('010101010')
asn1 = Krypt::ASN1::BitString.new(value)
s = "\x03\x03\x00\x00\xAA"

puts asn1.to_der == s

puts asn1.to_der.encoding
puts s.encoding




