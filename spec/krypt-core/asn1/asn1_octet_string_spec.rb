# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::OctetString do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::OctetString }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::OctetString
    class << self
      alias old_new new
      def new(*args)
        if args.size > 1
          args = [args[0], args[1], :IMPLICIT, args[2]]
        end
        old_new(*args)
      end
    end
  end

  describe '#new' do
    context 'gets value for construct' do
      subject { klass.new(value) }

      context 'accepts "hello,world!"' do
        let(:value) { 'hello,world!' }

        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 'hello,world!' }
        its(:infinite_length) { should == false }
      end

      context 'accepts (empty)' do
        let(:value) { '' }
        its(:value) { should == '' }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new('hello,world!', tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::OCTET_STRING }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new('hello,world!', Krypt::ASN1::OCTET_STRING, tag_class) }

      context 'accepts :UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :APPLICATION' do
        let(:tag_class) { :APPLICATION }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :PRIVATE' do
        let(:tag_class) { :PRIVATE }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        its(:tag_class) { should == tag_class }
      end
    end

    context 'when the 2nd argument is given but 3rd argument is omitted' do
      subject { klass.new('hello,world!', Krypt::ASN1::OCTET_STRING) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts "hello,world!"' do
        let(:value) { 'hello,world!' }

        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 'hello,world!' }
        its(:infinite_length) { should == false }
      end

      context 'accepts (empty)' do
        let(:value) { '' }
        its(:value) { should == '' }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::OCTET_STRING }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    describe '#tag_class' do
      subject { o = klass.new(nil); o.tag_class = tag_class; o }

      context 'accepts :UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :APPLICATION' do
        let(:tag_class) { :APPLICATION }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :PRIVATE' do
        let(:tag_class) { :PRIVATE }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        its(:tag_class) { should == tag_class }
      end
    end
  end

  describe '#to_der' do
    context 'encodes a given value' do
      subject { klass.new(value).to_der }

      context 'hello,world!' do
        let(:value) { 'hello,world!' }
        it { should == "\x04\x0Chello,world!" }
      end

      context '(empty)' do
        let(:value) { '' }
        it { should == "\x04\x00" }
      end

      context '999 octets' do
        let(:value) { 'x' * 999 }
        it { should == "\x04\x82\x03\xE7" + 'x' * 999 }
      end

      context '1000 octets' do
        let(:value) { 'x' * 1000 }
        it { should == "\x04\x82\x03\xE8" + 'x' * 1000 }
      end

      context '1001 octets' do
        let(:value) { 'x' * 1001 }
        it { should == "\x04\x82\x03\xE9" + 'x' * 1001 }
      end

      context 'nil' do
        let(:value) { nil }
        it { should == "\x04\x00" }
      end
    end

    context 'encodes tag number' do
      subject { klass.new('hello,world!', tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::OCTET_STRING }
        it { should == "\xC4\x0Chello,world!" }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == "\xCE\x0Chello,world!" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      subject { klass.new('hello,world!', Krypt::ASN1::OCTET_STRING, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x04\x0Chello,world!" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x44\x0Chello,world!" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x84\x0Chello,world!" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC4\x0Chello,world!" }
      end

      context 'IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        it { should == "\x84\x0Chello,world!" }
      end

      context 'EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        it { should == "\xA4\x0E\x04\x0Chello,world!" }
      end

      context nil do
        let(:tag_class) { nil }
        it { expect { subject }.to raise_error asn1error } # TODO: ossl does not check nil
      end

      context :no_such_class do
        let(:tag_class) { :no_such_class }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    context 'encodes values set via accessors' do
      subject {
        o = klass.new(nil)
        o.value = value if defined? value
        o.tag = tag if defined? tag
        o.tag_class = tag_class if defined? tag_class
        o.to_der
      }

      context 'value: 01010101' do
        let(:value) { 'hello,world!' }
        it { should == "\x04\x0Chello,world!" }
      end

      context 'custom tag' do
        let(:value) { 'hello,world!' }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xCE\x0Chello,world!" }
      end

      context 'tag_class' do
        let(:value) { 'hello,world!' }
        let(:tag_class) { :APPLICATION }
        it { should == "\x44\x0Chello,world!" }
      end
    end

    context "encodes infinite length constructed values" do
      subject do
        asn1 = klass.new(value)
        asn1.infinite_length = true
        asn1.to_der
      end

      context "UNIVERSAL primitive with explicit EOC" do
        let(:value) { [
          mod::OctetString.new("\x01"), 
          mod::OctetString.new("\x02"), 
          mod::EndOfContents.new
        ] }
        it { subject.should == "\x24\x80\x04\x01\x01\x04\x01\x02\x00\x00" }
      end

      context "UNIVERSAL primitive without explicit EOC" do
        let(:value) { [
          mod::OctetString.new("\x01"), 
          mod::OctetString.new("\x02"), 
        ] }
        it { subject.should == "\x24\x80\x04\x01\x01\x04\x01\x02\x00\x00" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { 'hello,world!' }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x04\x0Chello,world!" }
      end

      context "Object responds to :write" do
        let(:value) { 'hello,world!' }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x04\x0Chello,world!" }
      end

      context "raise IO error transparently" do
        let(:value) { 'hello,world!' }
        let(:io) { io_error_object }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new('hello,world!')
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'hello,world!' do
        let(:der) { "\x04\x0Chello,world!" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'hello,world!' }
      end

      context '(empty)' do
        let(:der) { "\x04\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == '' }
      end

      context '999 octets' do
        let(:der) { "\x04\x82\x03\xE7" + 'x' * 999 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'x' * 999 }
      end

      context '1000 octets' do
        let(:der) { "\x04\x82\x03\xE8" + 'x' * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'x' * 1000 }
      end

      context '1001 octets' do
        let(:der) { "\x04\x82\x03\xE9" + 'x' * 1001 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'x' * 1001 }
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x04\x0Chello,world!" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x44\x0Chello,world!" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x84\x0Chello,world!" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC4\x0Chello,world!" }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { "\x04\x0Chello,world!" }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == "\x84\x0Chello,world!"
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { "\x04\x0Chello,world!" }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == "\xA0\x0E\x04\x0Chello,world!" 
        end
      end

    end

    context 'infinite-length encoded octet string' do
      let(:der) { "\x24\x80\x04\x01\x00\x04\x01\x01\x00\x00" }
      its(:tag) { should == Krypt::ASN1::OCTET_STRING }
      its(:tag_class) { should == :UNIVERSAL }
      its(:infinite_length) { should == true }
      it '' do
        subject.should be_an_instance_of mod::OctetString
        subject.value.should respond_to :each
        subject.value.size.should == 2
        oct1 = subject.value[0]
        oct2 = subject.value[1]
        [oct1, oct2].each do |oct|
          oct.tag.should == Krypt::ASN1::OCTET_STRING
          oct.tag_class.should == :UNIVERSAL
        end
        oct1.value.should == "\x00"
        oct2.value.should == "\x01"
        subject.to_der.should == der
      end
    end
  end
end
