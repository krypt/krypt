# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::EndOfContents do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::EndOfContents }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #let(:klass) { mod::EndOfContent }

  describe '#new' do
    context 'constructs without value' do
      subject { klass.new }

      its(:tag) { should == Krypt::ASN1::END_OF_CONTENTS }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == nil } # TODO: ossl returns ''
      its(:infinite_length) { should == false }
    end

    context 'constructs with nil' do
      subject { klass.new(nil) }

      its(:tag) { should == Krypt::ASN1::END_OF_CONTENTS }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == nil }
      its(:infinite_length) { should == false }
    end

    it "only accepts nil as the value argument" do
      -> { klass.new(1) }.should raise_error(ArgumentError)
    end

    context "does not accept tag and tag_class arguments" do
      it { -> { klass.new(nil, 0) }.should raise_error(ArgumentError) }
      it { -> { klass.new(nil, 0, :UNIVERSAL) }.should raise_error(ArgumentError) }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts nil' do
        let(:value) { nil }
        its(:value) { should == nil }
      end

      it "accepts objects other than nil as the value argument, but raises on encoding" do
        asn1 = klass.new
        asn1.value = 1
        -> { asn1.to_der }.should raise_error asn1error
      end
    end
  end

  describe '#to_der' do
    context 'encodes without value' do
      subject { klass.new.to_der }
      it { should == "\x00\x00" }
    end

    context 'encodes a given value' do
      subject { klass.new(nil).to_der }
      it { should == "\x00\x00" }
    end

    context 'encodes values set via accessors' do
      subject {
        o = klass.new(nil)
        o.value = nil
        o.to_der
      }

      it { should == "\x00\x00" }
    end 
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { nil }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x00\x00" }
      end

      context "Object responds to :write" do
        let(:value) { nil }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x00\x00" }
      end

      context "raise IO error transparently" do
        let(:value) { nil }
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new(nil)
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      let(:der) { "\x00\x00" }
      its(:class) { should == klass }
      its(:tag) { should == Krypt::ASN1::END_OF_CONTENTS }
      its(:value) { should == nil }
    end

    context 'rejects values with a lenght > 0' do
      let(:der) { "\x00\x01\x00" }
      it { -> { subject.value }.should raise_error asn1error }
    end
  end
end
