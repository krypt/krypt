# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::Boolean do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::Boolean }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Boolean
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

      context 'accepts true' do
        let(:value) { true }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == true }
        its(:infinite_length) { should == false }
      end

      context 'accepts false' do
        let(:value) { false }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == false }
        its(:infinite_length) { should == false }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new(true, tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::BOOLEAN }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new(true, Krypt::ASN1::BOOLEAN, tag_class) }

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
      subject { klass.new(true, Krypt::ASN1::BOOLEAN) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts true' do
        let(:value) { true }
        its(:value) { should == true }
      end

      context 'accepts false' do
        let(:value) { false }
        its(:value) { should == false }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::BOOLEAN }
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

      context 'true' do
        let(:value) { true }
        it { should == "\x01\x01\xFF" }
      end

      context 'false' do
        let(:value) { false }
        it { should == "\x01\x01\x00" }
      end

      context 'nil' do
        let(:value) { nil }
        it { expect { subject }.to raise_error asn1error } # TODO: ossl does not check nil
      end

      context 'non true/false e.g. String' do
        let(:value) { 'hi!' }
        it { expect { subject }.to raise_error asn1error } # TODO: ossl does not check true/false
      end
    end

    context 'encodes tag number' do
      subject { klass.new(true, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::BOOLEAN }
        it { should == "\xC1\x01\xFF" }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == "\xCE\x01\xFF" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      subject { klass.new(true, Krypt::ASN1::BOOLEAN, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x01\x01\xFF" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x41\x01\xFF" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x81\x01\xFF" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC1\x01\xFF" }
      end

      context "IMPLICIT" do
        let(:tag_class) { :IMPLICIT }
        it { should == "\x81\x01\xFF" }
      end

      context "EXPLICIT" do
        let(:tag_class) { :EXPLICIT }
        it { should == "\xA1\x03\x01\x01\xFF" }
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

      context 'value: true' do
        let(:value) { true }
        it { should == "\x01\x01\xFF" }
      end

      context 'custom tag' do
        let(:value) { true }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xCE\x01\xFF" }
      end

      context 'tag_class' do
        let(:value) { true }
        let(:tag_class) { :APPLICATION }
        it { should == "\x41\x01\xFF" }
      end
    end

    it "preserves a BER-encoded value when encoding it again" do
      ber = "\x01\x01\x01"
      decoder.decode(ber).to_der.should == ber
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { true }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x01\x01\xFF" }
      end

      context "Object responds to :write" do
        let(:value) { true }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x01\x01\xFF" }
      end

      context "raise IO error transparently" do
        let(:value) { true }
        let(:io) { io_error_object }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new(true)
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'true' do
        let(:der) { "\x01\x01\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:value) { should == true }
      end

      context 'false' do
        let(:der) { "\x01\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:value) { should == false }
      end

      context 'allow to decode non-DER true' do
        let(:der) { "\x01\x01\x01" } # non 0xFF is true in BER
        its(:class) { should == klass }
        its(:value) { should == true }
      end

      context 'rejects values whose length is > 1' do
       let(:der) { "\x01\x02\x01\x01" }
       it { expect { subject.value }.to raise_error asn1error }
      end 
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x01\x01\xFF" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x41\x01\xFF" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x81\x01\xFF" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC1\x01\xFF" }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { "\x01\x01\xFF" }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == "\x81\x01\xFF"
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { "\x01\x01\xFF" }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == "\xA0\x03\x01\x01\xFF" 
        end
      end
    end
  end
end
