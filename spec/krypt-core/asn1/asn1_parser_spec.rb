# encoding: US-ASCII

require 'rspec'
require 'krypt'
require_relative '../resources'
require 'stringio'

def do_and_close(io)
  yield io
  io.close
end

describe Krypt::ASN1::Parser do 

  it "can be instantiated with default constructor" do 
    Krypt::ASN1::Parser.new.should be_an_instance_of Krypt::ASN1::Parser
  end

  it "takes no arguments in its constructor" do
    lambda { Krypt::ASN1::Parser.new(Object.new) }.should raise_error(ArgumentError)
  end

  it "should be reusable for several IOs" do
    parser = Krypt::ASN1::Parser.new
    io = Resources.certificate_io
    do_and_close(io) { |io| parser.next(io).should_not be_nil }
    io = Resources.certificate_io
    do_and_close(io) { |io| parser.next(io).should_not be_nil }
  end
  
end

describe Krypt::ASN1::Parser, "#next" do

  subject { Krypt::ASN1::Parser.new }

  it "returns a Header when called on an IO representing an ASN.1" do
    io = Resources.certificate_io
    do_and_close(io) { |io| parse_next io }
    parse_next(StringIO.new(Resources.certificate))
  end

  it "raises an ArgumentError when called on a String. A String does not 
      provide internal state that would be needed for parsing." do
    lambda { parse_next(Resources.certificate) }.should raise_error(ArgumentError)
  end

  def parse_next(io)
    subject.next(io).should be_an_instance_of Krypt::ASN1::Header
  end

  it "raises ArgumentError if anything other than an IO is passed. Rejection
      is handled depending on the presence of a #read method." do
    lambda { subject.next(:sym) }.should raise_error(ArgumentError)
    
    c = Class.new do
      def initialize
        @io = Resources.certificate_io
      end

      def read(len=nil, buf=nil)
        @io.read(len, buf)
      end
    end
    
    parse_next(c.new)
  end

  it "does not close the underlying IO after reading it" do
    io = Resources.certificate_io
    subject.next(io).skip_value
    subject.next(io).should be_nil
    io.closed?.should be_false
    io.close
    io.closed?.should be_true
  end

  it "reads nested Headers when called subsequently for constructed values" do
    num_headers = 0
    io = Resources.certificate_io
    while header = subject.next(io)
      num_headers += 1
      next if header.constructed?
      header.skip_value #need to consume the values
    end
    num_headers.should > 1
    io.close
  end 

  it "also reads singular, non-constructed values" do
    io = Resources.bytes_to_io( %w{02 01 01} )
    header = subject.next(io)
    header.tag.should == 2
    header.size.should == 1
    header.header_size.should == 2
    header.tag_class.should == :UNIVERSAL
    header.constructed?.should be_false
    header.infinite?.should be_false
    header.value.should == "\x01"
  end

  it "yields the original contents for the header and the value of the
      initial sequence" do
    cert = Resources.certificate
    io = StringIO.new cert
    header = subject.next io
    value = header.value
    (header.header_size + value.size).should == cert.size
    ("" << header.bytes << value).should == cert
  end

  it "yields the original contents for the nested headers and their values" do
    cert = Resources.certificate
    io = StringIO.new cert
    out = ""
    while header = subject.next(io)
      out << header.bytes
      next if header.constructed?
      val = header.value
      out << val unless val == nil
    end
    out.should == cert
  end

end

describe Krypt::ASN1::Header do
  
  it "cannot be instantiated" do
    lambda { Krypt::ASN1::Header.new }.should raise_error
  end
  
end

describe Krypt::ASN1::Header, "#tag" do

  subject { Krypt::ASN1::Parser.new }

  it "yields the tag of an ASN1 value, both for simple and complex tags" do
    simple = Resources.bytes_to_io( %w{05 00} )
    header = subject.next(simple)
    header.tag.should == 5
  end

  it "yields the tag for complex tags with a single octet" do
    complex_single_octet = %w{df 2a 01}
    complex_single_octet_v = Resources.bytes_to_io(Array.new(complex_single_octet) << '00')
    header = subject.next(complex_single_octet_v)
    header.tag.should == 42
  end

  it "yields the tag for complext tags with multiple octets" do
    complex_two_octets = %w{5f 82 2c 01} 
    complex_two_octets_v = Resources.bytes_to_io(Array.new(complex_two_octets) << '00')
    header = subject.next(complex_two_octets_v)
    header.tag.should == 300
  end

end

describe Krypt::ASN1::Header, "#tag_class" do

  it "recognizes UNIVERSAL, CONTEXT_SPEICIFIC, APPLICATION and PRIVATE" do
    subject = Krypt::ASN1::Parser.new
    universal = Resources.bytes_to_io( %w{05 00} )
    header = subject.next(universal)
    header.tag_class.should == :UNIVERSAL
    context_specific = Resources.bytes_to_io( %w{81 00} )
    header = subject.next(context_specific)
    header.tag_class.should == :CONTEXT_SPECIFIC
    private_tc = Resources.bytes_to_io( %w{df 2a 01} )
    header = subject.next(private_tc)
    header.tag_class.should == :PRIVATE
    application = Resources.bytes_to_io( %w{5f 82 2c 01} )
    header = subject.next(application)
    header.tag_class.should == :APPLICATION
  end

end

describe Krypt::ASN1::Header, "#constructed?" do

  subject { Krypt::ASN1::Parser.new }

  it "returns false for primitive values" do
    evaluate(%w{05 00}, false)
    evaluate(%w{81 00}, false)
    evaluate(%w{df 2a 01}, false) 
    evaluate(%w{5f 82 2c 01}, false)
  end

  it "returns true for constructed values" do
    evaluate(%w{30 03 02 01 01}, true)
    evaluate(%w{31 03 02 01 01}, true)
    evaluate(%w{30 80 02 01 01 00 00}, true)
    evaluate(%w{24 80 04 01 01 00 00}, true)
  end

  def evaluate(bytes, expectation)
    io = Resources.bytes_to_io bytes
    header = subject.next io
    header.constructed?.should == expectation
  end

end

describe Krypt::ASN1::Header, "#infinite?" do
  
  subject { Krypt::ASN1::Parser.new }

  it "returns false for definite length values" do
    evaluate(%w{05 00}, false)
    evaluate(%w{81 00}, false)
    evaluate(%w{df 2a 01}, false) 
    evaluate(%w{5f 82 2c 01}, false)
    evaluate(%w{30 03 02 01 01}, false)
    evaluate(%w{31 03 02 01 01}, false)
  end

  it "returns true for infinite length values" do
    evaluate(%w{30 80 02 01 01 00 00}, true)
    evaluate(%w{31 80 02 01 01 00 00}, true)
    evaluate(%w{24 80 04 01 01 00 00}, true)
  end

  it "raises an error for infinite length primitive values" do
    lambda { evaluate(%w{04 80 04 01 01 00 00}, true) }.should raise_error(Krypt::ASN1::ParseError)
  end

  def evaluate(bytes, expectation)
    io = Resources.bytes_to_io bytes
    header = subject.next io
    header.infinite?.should == expectation
  end

end

describe Krypt::ASN1::Header, "#size" do

  subject { Krypt::ASN1::Parser.new }

  it "returns the size of the value for single octet lengths" do
    simple = Resources.bytes_to_io( %w{02 01 01} )
    header = subject.next(simple)
    header.size.should == 1
  end

  it "returns the size of the value for multiple octet lengths" do
    complex = Resources.bytes_to_io( %w{04 82 03 e8} << ('a' * 1000))
    header = subject.next complex
    header.size.should == 1000
  end

  it "returns 0 for missing values" do
    null = %w{05 00}
    eoc = %w{00 00}
    subject.next(Resources.bytes_to_io(null)).size.should == 0
    subject.next(Resources.bytes_to_io(eoc)).size.should == 0
  end

  it "returns 0 for infinite length values" do
    inf = %w{30 80 02 01 01 00 00}
    subject.next(Resources.bytes_to_io(inf)).size.should == 0
  end

end

describe Krypt::ASN1::Header, "#header_size" do

  subject { Krypt::ASN1::Parser.new }

  it "returns the size of the sum of tag plus length encoding
      for simple tags" do
    simple = Resources.bytes_to_io( %w{05 00} )
    header = subject.next(simple)
    header.header_size.should == 2
  end

  it "returns the size of the sum of tag plus length encoding
      for complex tags with a single octet" do
    complex_single_octet = %w{df 2a 01}
    complex_single_octet_v = Resources.bytes_to_io(Array.new(complex_single_octet) << '00')
    header = subject.next(complex_single_octet_v)
    header.header_size.should == 3
  end

  it "returns the size of the sum of tag plus length encoding
      for complex tags with multiple octets" do
    complex_two_octets = %w{5f 82 2c 01} 
    complex_two_octets_v = Resources.bytes_to_io(Array.new(complex_two_octets) << '00')
    header = subject.next(complex_two_octets_v)
    header.header_size.should == 4
  end

  it "returns the size of the header for multiple octet lengths" do
    complex = Resources.bytes_to_io( %w{04 82 03 e8} << ('a' * 1000))
    header = subject.next complex
    header.header_size.should == 4
  end

end

describe Krypt::ASN1::Header, "#skip_value" do

  it "skips to the end of the file when asked to skip the value of a
      starting constructed value" do
    skip_value(StringIO.new(Resources.certificate))
    skip_value Resources.certificate_io
  end

  def skip_value(io)
    parser = Krypt::ASN1::Parser.new
    header = parser.next(io)
    header.skip_value
    parser.next(io).should be_nil
  end

end

describe Krypt::ASN1::Header, "#value" do

  subject { Krypt::ASN1::Parser.new }

  it "caches the value of a header once it was read" do
    io = Resources.certificate_io
    begin
      header = subject.next(io)
      header.value.should == header.value
    ensure
      io.close
    end
  end

  it "returns nil for missing values" do
    null = %w{05 00}
    eoc = %w{00 00}
    subject.next(Resources.bytes_to_io(null)).value.should be_nil
    subject.next(Resources.bytes_to_io(eoc)).value.should be_nil 
  end

  it "has Encoding::BINARY" do
    io = Resources.certificate_io
    begin
      subject.next(io).value.encoding.should == Encoding::BINARY
    ensure
      io.close
    end
  end

end

describe Krypt::ASN1::Header, "#value_io" do

  subject { Krypt::ASN1::Parser.new }

  it "returns an IO that reads the entire value of a definite sequence" do
    cert = Resources.certificate_io
    header = subject.next cert
    (header.bytes << header.value_io.read).should == Resources.certificate
    cert.close
  end

  it "returns an IO whose content is in Encoding::BINARY" do
    cert = Resources.certificate_io
    header = subject.next cert
    header.value_io.read.encoding.should == Encoding::BINARY
    cert.close
  end

  it "reads the values excluding the headers for an infinite length primitive
      value by default" do
    io = Resources.bytes_to_io( %w{24 80 04 01 01 04 01 02 00 00} )
    expected = [%w{01 02}.join('')].pack('H*')
    header = subject.next io
    header.value_io.read.should == expected
  end
 
  it "reads the values including the headers for an infinite length primitive
      value when passed false as a parameter" do
    io = Resources.bytes_to_io( %w{24 80 04 01 01 04 01 02 00 00} )
    expected = [%w{04 01 01 04 01 02 00 00}.join('')].pack('H*')
    header = subject.next io
    header.value_io(false).read.should == expected
  end

  it "reads the values excluding the headers for an infinite length sequence
      by default" do
    io = Resources.bytes_to_io( %w{30 80 04 01 01 04 01 02 00 00} )
    expected = [%w{01 02}.join('')].pack('H*')
    header = subject.next io
    header.value_io.read.should == expected
  end
 
  it "reads the values including the headers for an infinite length sequence
      when passed false as a parameter" do
    io = Resources.bytes_to_io( %w{30 80 04 01 01 04 01 02 00 00} )
    expected = [%w{04 01 01 04 01 02 00 00}.join('')].pack('H*')
    header = subject.next io
    header.value_io(false).read.should == expected
  end

  it "caches an IO if requested for a header more than once" do
    io = Resources.certificate_io
    header = subject.next io
    header.value_io
    lambda { header.value_io }.should_not raise_error
    io.close
  end

  it "raises an error if the value of a header is requested after requesting
    an IO" do
    io = Resources.certificate_io
    header = subject.next io
    header.value_io
    lambda { header.value }.should raise_error(Krypt::ASN1::ParseError)
    io.close
  end

  it "raises an error if an IO after reading the value of the header" do
    io = Resources.certificate_io
    header = subject.next io
    header.value
    lambda { header.value_io }.should raise_error(Krypt::ASN1::ParseError)
    io.close
  end

  it "is stateful wrt to the amount of data already read" do
    io = Resources.certificate_io
    header = subject.next io
    header.value_io.read.should_not == ""
    header.value_io.read.should == ""
    io.close
  end

  it "returns an 'empty' IO for missing values" do
    null = %w{05 00}
    eoc = %w{00 00}
    subject.next(Resources.bytes_to_io(null)).value_io.read.should == ""
    subject.next(Resources.bytes_to_io(eoc)).value_io.read.should == "" 
  end

end

describe Krypt::ASN1::Header, "#bytes" do

  subject { Krypt::ASN1::Parser.new }

  it "returns the encoding of a parsed header" do
    complex_two_octets = %w{5f 82 2c 01} 
    complex_two_octets_v = Resources.bytes_to_io(Array.new(complex_two_octets) << '00')
    header = subject.next(complex_two_octets_v)
    header.bytes.should == Resources.bytes(complex_two_octets)
  end

  it "returns the encoding of a simple tag" do
    raw = %w{05 00}
    simple = Resources.bytes_to_io(raw)
    header = subject.next(simple)
    header.bytes.should == Resources.bytes(raw) 
  end

  it "returns the encoding for complex tags with a single octet" do
    complex_single_octet = %w{df 2a 01}
    complex_single_octet_v = Resources.bytes_to_io(Array.new(complex_single_octet) << '00')
    header = subject.next(complex_single_octet_v)
    header.bytes.should == Resources.bytes(complex_single_octet)
  end

  it "returns the encoding for complex tags with multiple octets" do
    complex_two_octets = %w{5f 82 2c 01} 
    complex_two_octets_v = Resources.bytes_to_io(Array.new(complex_two_octets) << '00')
    header = subject.next(complex_two_octets_v)
    header.bytes.should == Resources.bytes(complex_two_octets)
  end

  it "returns the encoding for multiple octet lengths" do
    raw = %w{04 82 03 e8}
    complex = Resources.bytes_to_io( Array.new(raw) << ('a' * 1000))
    header = subject.next complex
    header.bytes.should == Resources.bytes(raw) 
  end

  it "has Encoding::BINARY" do
    raw = %w{05 00}
    io = Resources.bytes_to_io(raw)
    subject.next(io).bytes.encoding.should == Encoding::BINARY
  end

end

describe Krypt::ASN1::Header, "#encode_to" do

  it "encodes the header to an IO" do
    null = %w{05 00}
    io = Resources.bytes_to_io(null)
    header = Krypt::ASN1::Parser.new.next io
    out = StringIO.new
    header.encode_to(out)
    out.string.should == header.bytes
  end

end

