require_relative 'helper'
require 'stringio'

class Krypt::ASN1Test < Test::Unit::TestCase

  def test_parse_encode_equality_file
    io = Resources.certificate_io
    begin
      asn1 = Krypt::ASN1.decode(io)
      cert = Resources.certificate
      assert_equal(cert, asn1.to_der)
      assert_equal_streaming(cert, asn1)
    ensure
      io.close
    end
  end

  def test_parse_encode_equality_string_io
    io = StringIO.new(Resources.certificate)
    asn1 = Krypt::ASN1.decode(io)
    cert = Resources.certificate
    assert_equal(cert, asn1.to_der)
    assert_equal_streaming(cert, asn1)
  end

  def test_parse_encode_equality_string
    asn1 = Krypt::ASN1.decode(Resources.certificate)
    cert = Resources.certificate
    assert_equal(cert, asn1.to_der)
    assert_equal_streaming(cert, asn1)
  end

  def test_attributes
    raw = [%w{30 06 04 01 01 02 01 01}.join("")].pack("H*")
    asn1 = Krypt::ASN1.decode(raw)
    assert_universal(Krypt::ASN1::SEQUENCE, asn1)
    seq = asn1.value
    assert_equal(2, seq.size)
    octet = seq[0]
    assert_universal(Krypt::ASN1::OCTET_STRING, octet)
    assert_equal("\1", octet.value)
    integer = seq[1]
    assert_universal(Krypt::ASN1::INTEGER, integer)
    assert_equal(1, integer.value)
    
    assert_equal(raw, asn1.to_der)
  end

  def test_parse_infinite_length_sequence
    raw = [%w{30 80 04 01 01 02 01 01 00 00}.join("")].pack("H*")
    asn1 = Krypt::ASN1.decode(raw)
    assert_universal(Krypt::ASN1::SEQUENCE, asn1, true)
    seq = asn1.value
    assert_equal(3, seq.size)
    octet = seq[0]
    assert_universal(Krypt::ASN1::OCTET_STRING, octet)
    assert_equal("\1", octet.value)
    integer = seq[1]
    assert_universal(Krypt::ASN1::INTEGER, integer)
    assert_equal(1, integer.value)
    eoc = seq[2]
    assert_universal(Krypt::ASN1::END_OF_CONTENTS, eoc)
    assert_nil(eoc.value)
    
    assert_equal(raw, asn1.to_der)
  end

  def test_parse_infinite_length_octet_string
    raw = [%w{24 80 04 01 01 04 01 02 00 00}.join("")].pack("H*")
    asn1 = Krypt::ASN1.decode(raw)
    assert_universal(Krypt::ASN1::OCTET_STRING, asn1, true)
    assert_equal(true, asn1.is_a?(Krypt::ASN1::Constructive))
    seq = asn1.value
    assert_equal(3, seq.size)
    octet1 = seq[0]
    assert_universal(Krypt::ASN1::OCTET_STRING, octet1)
    assert_equal("\1", octet1.value)
    octet2 = seq[1]
    assert_universal(Krypt::ASN1::OCTET_STRING, octet2)
    assert_equal("\2", octet2.value)
    eoc = seq[2]
    assert_universal(Krypt::ASN1::END_OF_CONTENTS, eoc)
    assert_nil(eoc.value)
    
    assert_equal(raw, asn1.to_der)
  end

  def test_each
    [%w{30 06 04 01 01 02 01 01},
     %w{31 06 04 01 01 02 01 01},
     %w{24 80 04 01 01 04 01 02 00 00}].each do |raw|
      val = [raw.join("")].pack("H*")
      cons_header = Krypt::ASN1::Parser.new.next(StringIO.new(val))
      io = StringIO.new
      cons_header.encode_to(io)
      asn1 = Krypt::ASN1.decode(val)
      asn1.each do |value|
        value.encode_to(io)
      end
      assert_equal(val, io.string.force_encoding("ASCII-8BIT"))
    end
  end

  private

  def assert_universal(tag, asn1, inf_len=false)
    assert_equal(tag, asn1.tag)
    assert_equal(:UNIVERSAL, asn1.tag_class)
    assert_equal(inf_len, asn1.infinite_length)
  end

  def assert_equal_streaming(raw, asn1)
    io = StringIO.new
    asn1.encode_to(io)
    assert_equal(raw, io.string.force_encoding("ASCII-8BIT"))
  end

end

