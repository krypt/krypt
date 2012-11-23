require 'rspec'
require 'krypt'
require 'base64'
require_relative './resources'
require_relative '../resources'

describe Krypt::ASN1 do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  def create_pem_b64(b64, name)
      "-----BEGIN #{name}-----\n#{b64}-----END #{name}-----\n"
  end

  describe "#decode" do
    subject { decoder.decode(value) }

    context "accepts regular DER-encoded values" do
      let(:value) { "\x02\x01\x01" }
      its(:tag) { should == Krypt::ASN1::INTEGER }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 1 }
      its(:infinite_length) { should == false }
    end

    context "also accepts PEM-encoded values" do
      let(:value) { create_pem_b64(Base64.encode64("\x02\x01\x01"), "INTEGER") }
      its(:tag) { should == Krypt::ASN1::INTEGER }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 1 }
      its(:infinite_length) { should == false }
    end

    context "accepts IO" do
      subject do
        begin
          decoder.decode(io)
        ensure
          io.close
        end
      end

      context "regular DER-encoded IO" do
        let(:io) { Resources.certificate_io }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "regular PEM-encoded IO" do
        let(:io) { Resources.certificate_pem_io }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "regular DER-encoded StringIO" do
        let(:io) { StringIO.new(Resources.certificate) }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "regular PEM-encoded StringIO" do
        let(:io) { StringIO.new(Resources.certificate_pem) }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "DER-encoded IO-like value that does not support rewinding" do
        let(:io) do
          c = Class.new do
            def initialize
              @io = Resources.certificate_io
            end

            def read(len=nil, buf=nil)
              @io.read(len, buf)
            end

            def seek(amount, whence=IO::SEEK_SET)
              raise RuntimeError.new
            end

            def close
              @io.close
            end
          end
          c.new
        end

        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "PEM-encoded IO-like value that does not support rewinding" do
        let(:io) do
          c = Class.new do
            def initialize
              @io = Resources.certificate_pem_io
            end

            def read(len=nil, buf=nil)
              @io.read(len, buf)
            end

            def seek(amount, whence=IO::SEEK_SET)
              raise RuntimeError.new
            end

            def close
              @io.close
            end
          end
          c.new
        end

        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end
    end
  end

  describe "#decode_der" do
    subject { decoder.decode_der(value) }

    context "accepts regular DER-encoded values" do
      let(:value) { "\x02\x01\x01" }
      its(:tag) { should == Krypt::ASN1::INTEGER }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 1 }
      its(:infinite_length) { should == false }
    end

    context "accepts IO" do
      subject do
        begin
          decoder.decode_der(io)
        ensure
          io.close
        end
      end

      context "regular DER-encoded IO" do
        let(:io) { Resources.certificate_io }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "regular DER-encoded StringIO" do
        let(:io) { StringIO.new(Resources.certificate) }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "DER-encoded IO-like value that does not support rewinding" do
        let(:io) do
          c = Class.new do
            def initialize
              @io = Resources.certificate_io
            end

            def read(len=nil, buf=nil)
              @io.read(len, buf)
            end

            def seek(amount, whence=IO::SEEK_SET)
              raise RuntimeError.new
            end

            def close
              @io.close
            end
          end
          c.new
        end

        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end
    end
  end

  describe "#decode_pem" do
    subject { decoder.decode_pem(value) }

    context "accepts regular PEM-encoded values" do
      let(:value) { create_pem_b64(Base64.encode64("\x02\x01\x01"), "INTEGER") }
      its(:tag) { should == Krypt::ASN1::INTEGER }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 1 }
      its(:infinite_length) { should == false }
    end

    context "accepts IO" do
      subject do
        begin
          decoder.decode_pem(io)
        ensure
          io.close
        end
      end

      context "regular PEM-encoded IO" do
        let(:io) { Resources.certificate_pem_io }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "regular PEM-encoded StringIO" do
        let(:io) { StringIO.new(Resources.certificate_pem) }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end

      context "PEM-encoded IO-like value that does not support rewinding" do
        let(:io) do
          c = Class.new do
            def initialize
              @io = Resources.certificate_pem_io
            end

            def read(len=nil, buf=nil)
              @io.read(len, buf)
            end

            def seek(amount, whence=IO::SEEK_SET)
              raise RuntimeError.new
            end

            def close
              @io.close
            end
          end
          c.new
        end

        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:infinite_length) { should == false }
        its(:value) { should be_an_instance_of Array }
        its(:to_der) { should == Resources.certificate }
      end
    end
  end
end
 
