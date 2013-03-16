require_relative 'helper'
require 'stringio'

class Krypt::ParserTest < Test::Unit::TestCase

  def test_parse_and_skip_top_level_file
    parse_and_skip_top_level(Resources.certificate_io)
  end

  def test_parse_and_skip_top_level_string_io
    parse_and_skip_top_level(StringIO.new(Resources.certificate))
  end

  def test_parse_and_skip_file
    parse_and_skip(Resources.certificate_io)
  end

  def test_parse_and_skip_string_io
    parse_and_skip(StringIO.new(Resources.certificate))
  end

  def test_consume_top_level_streaming_file
    consume_top_level_streaming(Resources.certificate_io)
  end

  def test_consume_top_level_streaming_string_io
    consume_top_level_streaming(StringIO.new(Resources.certificate))
  end

  def test_consume_top_level_at_once_file
    consume_top_level_at_once(Resources.certificate_io)
  end

  def test_consume_top_level_at_once_string_io
    consume_top_level_at_once(StringIO.new(Resources.certificate))
  end

  def test_consume_all_streaming_file
    consume_all_streaming(Resources.certificate_io)
  end

  def test_consume_all_streaming_string_io
    consume_all_streaming(StringIO.new(Resources.certificate))
  end

  def test_consume_all_at_once_file
    consume_all_at_once(Resources.certificate_io)
  end

  def test_consume_all_at_once_string_io
    consume_all_at_once(StringIO.new(Resources.certificate))
  end

  def test_parse_tokens_methods_file
    parse_tokens_test_methods(Resources.certificate_io)
  end

  def test_parse_tokens_methods_string_io
    parse_tokens_test_methods(StringIO.new(Resources.certificate))
  end

  def test_parse_primitive
    raw = [%w{02 02 01 00}.join("")].pack("H*")
    parser = Krypt::ASN1::Parser.new
    io = StringIO.new(raw)
    header = parser.next(io)
    assert_equal(Krypt::ASN1::INTEGER, header.tag)
    assert_equal(:UNIVERSAL, header.tag_class)
    assert_equal(false, header.constructed?)
    assert_equal(false, header.infinite?)
    assert_equal(2, header.length)
    assert_equal(2, header.header_length)
    assert_header_value_equal(raw, header)
  end


  def test_parse_constructed
    raw = [%w{30 02 80 01 00}.join("")].pack("H*")
    parser = Krypt::ASN1::Parser.new
    io = StringIO.new(raw)
    header = parser.next(io)
    assert_equal(Krypt::ASN1::SEQUENCE, header.tag)
    assert_equal(:UNIVERSAL, header.tag_class)
    assert_equal(true, header.constructed?)
    assert_equal(false, header.infinite?)
    assert_equal(2, header.length)
    assert_equal(2, header.header_length)
    header = parser.next(io)
    assert_equal(0, header.tag)
    assert_equal(:CONTEXT_SPECIFIC, header.tag_class)
    assert_equal(false, header.constructed?)
    assert_equal(false, header.infinite?)
    assert_equal(1, header.length)
    assert_equal(2, header.header_length)
    assert_equal("\0", header.value)
    assert_nil(parser.next(io))
  end

  def test_complex_length
    raw = [%w{04 82 03 e8}.join("")].pack("H*")
    raw << "\0" * 1000
    io = StringIO.new(raw)
    parser = Krypt::ASN1::Parser.new
    header = parser.next(io)
    assert_equal(Krypt::ASN1::OCTET_STRING, header.tag)
    assert_equal(:UNIVERSAL, header.tag_class)
    assert_equal(false, header.constructed?)
    assert_equal(false, header.infinite?)
    assert_equal(1000, header.length)
    assert_equal(4, header.header_length)
    assert_header_value_equal(raw, header)
  end

  def test_complex_length_single_octet
    raw = [%w{df 2a 01 00}.join("")].pack("H*")
    parser = Krypt::ASN1::Parser.new
    io = StringIO.new(raw)
    header = parser.next(io)
    assert_equal(42, header.tag)
    assert_equal(:PRIVATE, header.tag_class)
    assert_equal(false, header.constructed?)
    assert_equal(false, header.infinite?)
    assert_equal(1, header.length)
    assert_equal(3, header.header_length)
    assert_header_value_equal(raw, header)
  end

  def test_complex_tag_two_octets
    raw = [%w{5f 82 2c 01 00}.join("")].pack("H*")
    parser = Krypt::ASN1::Parser.new
    io = StringIO.new(raw)
    header = parser.next(io)
    assert_equal(300, header.tag)
    assert_equal(:APPLICATION, header.tag_class)
    assert_equal(false, header.constructed?)
    assert_equal(false, header.infinite?)
    assert_equal(1, header.length)
    assert_equal(4, header.header_length)
    assert_header_value_equal(raw, header)
  end

  def test_inf_length_parsing_at_once_string_io
    inf_length_parsing_streaming_string_io(:AT_ONCE)
  end

  def test_inf_length_parsing_streaming_string_io
    inf_length_parsing_streaming_string_io(:STREAMING)
  end

  def test_inf_length_parsing_streaming_fixed_buffer_string_io
    inf_length_parsing_streaming_string_io(:STREAMING_FIXED)
  end

  def test_inf_length_parsing_at_once_values_only_string_io
    inf_length_parsing_streaming_string_io(:AT_ONCE, true)
  end

  def test_inf_length_parsing_streaming_values_only_string_io
    inf_length_parsing_streaming_string_io(:STREAMING, true)
  end

  def test_inf_length_parsing_streaming_fixed_buffer_values_only_string_io
    inf_length_parsing_streaming_string_io(:STREAMING_FIXED, true)
  end

  private

  def parse_and_skip_top_level(io)
    parser = Krypt::ASN1::Parser.new
    header = parser.next(io)
    assert_equal(Krypt::ASN1::SEQUENCE, header.tag)
    assert_equal(:UNIVERSAL, header.tag_class)
    assert(header.constructed?)
    assert(!header.infinite?)
    assert_equal(Resources.certificate.size, header.header_size + header.size)
    header.skip_value
    assert_nil(parser.next(io))
  ensure
    io.close
  end

  def parse_and_skip(io)
    parser = Krypt::ASN1::Parser.new
    num_tokens = 0
    while header = parser.next(io)
      num_tokens += 1
      unless header.constructed?
        header.skip_value
      end
    end
    assert(num_tokens > 1)
  ensure
    io.close
  end

  def consume_top_level_streaming(io)
    parser = Krypt::ASN1::Parser.new
    header = parser.next(io)
    stream = header.value_io
    consume_streaming(stream)
    assert_nil(parser.next(io))
  ensure
    io.close
  end

  def consume_top_level_at_once(io)
    parser = Krypt::ASN1::Parser.new
    header = parser.next(io)
    stream = header.value_io
    stream.read
    assert_nil(parser.next(io))
  ensure
    io.close
  end

  def consume_all_streaming(io)
    parser = Krypt::ASN1::Parser.new
    while header = parser.next(io)
      unless header.constructed?
        stream = header.value_io
        consume_streaming(stream)
      end
    end
    assert_nil(parser.next(io))
  ensure
    io.close
  end

  def consume_all_at_once(io)
    parser = Krypt::ASN1::Parser.new
    while header = parser.next(io)
      unless header.constructed?
        stream = header.value_io
        stream.read
      end
    end
    assert_nil(parser.next(io))
  ensure
    io.close
  end

  def parse_tokens_test_methods(io)
    parser = Krypt::ASN1::Parser.new
    while header = parser.next(io)
      assert_not_nil(header.tag)
      assert_not_nil(header.tag_class)
      assert_not_nil(header.size)
      assert_not_nil(header.length)
      assert_not_nil(header.header_size)
      assert_not_nil(header.header_length)
      assert_not_nil(header.constructed?)
      assert_not_nil(header.infinite?)
      unless header.constructed?
        if (header.tag == Krypt::ASN1::NULL || header.tag == Krypt::ASN1::END_OF_CONTENTS)
          assert_nil(header.value)
        else
          assert_not_nil(header.value)
        end
      end
    end
  ensure
    io.close
  end

  def inf_length_parsing_streaming_string_io(mode, values_only=false)
    raw = [%w{24 80 04 01 01 04 01 02 00 00}.join("")].pack("H*")
    io = StringIO.new(raw)
    parser = Krypt::ASN1::Parser.new
    header = parser.next(io)
    assert_equal(Krypt::ASN1::OCTET_STRING, header.tag)
    assert_equal(:UNIVERSAL, header.tag_class)
    assert_equal(true, header.constructed?)
    assert_equal(true, header.infinite?)
    assert_equal(0, header.length)
    assert_equal(2, header.header_length)
    value_io = header.value_io(values_only)

    result = StringIO.new("", "wb")
    unless values_only
      header.encode_to(result)
    end

    case mode
    when :AT_ONCE
      result << value_io.read
    when :STREAMING
      buf = nil
      while buf = value_io.read(3, buf)
        result << buf
      end
    when :STREAMING_FIXED
      buf = ""
      while value_io.read(3, buf)
        result << buf
      end
    end
  
    if values_only
      assert_equal( [%w{01 02}.join("")].pack("H*"), result.string)
    else
      assert_equal(raw, result.string.force_encoding("ASCII-8BIT"))
    end
  end

  def consume_streaming(io)
    buffer = ""
    while io.read(3, buffer)
    end
  end

  def assert_header_value_equal(expected, header)
    io = StringIO.new()
    header.encode_to(io)
    io << header.value
    assert_equal(expected, io.string.force_encoding("ASCII-8BIT"))
  end

end

