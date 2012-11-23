# -*- encoding: utf-8 -*-

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::UTF8String do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::UTF8String }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::UTF8String
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
  
  def _A(str)
    str.force_encoding("ASCII-8BIT")
  end

  describe '#new' do
    context 'gets value for construct' do
      subject { klass.new(value) }

      context 'accepts Japanese UTF-8 string' do
        let(:value) { 'こんにちは、世界！' }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts Japanese EUC-JP string' do
        let(:value) { 'こんにちは、世界！'.encode("EUC-JP") }
        its(:value) { should == value } # TODO: auto convert to UTF-8? raise?
      end

      context 'accepts empty String' do
        let(:value) { '' }
        its(:value) { should == value }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new('こんにちは、世界！', tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::UTF8_STRING }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new('こんにちは、世界！', Krypt::ASN1::UTF8_STRING, tag_class) }

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
      subject { klass.new('こんにちは、世界！', Krypt::ASN1::UTF8_STRING) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts Japanese UTF-8 string' do
        let(:value) { 'こんにちは、世界！' }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts Japanese EUC-JP string' do
        let(:value) { 'こんにちは、世界！'.encode("EUC-JP") }
        its(:value) { should == value } # TODO: auto convert to UTF-8? raise?
      end

      context 'accepts empty String' do
        let(:value) { '' }
        its(:value) { should == value }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::UTF8_STRING }
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

      context 'こんにちは、世界！' do
        let(:value) { 'こんにちは、世界！' }
        it { should == _A("\x0C\x18" + value) }
      end

      context '(empty)' do
        let(:value) { '' }
        it { should == "\x0C\x00" }
      end

      context '1000 octets' do
        let(:value) { 'あ' * 1000 }
        it { should == _A("\x0C\x82\x1F\x40" + value) }
      end

      context 'nil' do
        let(:value) { nil }
        it { should == "\x0C\x00" }
      end
    end

    context 'encodes tag number' do
      let(:value) { 'こんにちは、世界！' }
      subject { klass.new(value, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::UTF8_STRING }
        it { should == _A("\xCC\x18" + value) }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == _A("\xCE\x18" + value) }
      end

      context 'nil' do
        let(:tag) { nil }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      let(:value) { 'こんにちは、世界！' }
      subject { klass.new(value, Krypt::ASN1::UTF8_STRING, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == _A("\x0C\x18" + value) }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == _A("\x4C\x18" + value) }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == _A("\x8C\x18" + value) }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == _A("\xCC\x18" + value) }
      end

      context 'IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        it { should == _A("\x8C\x18" + value) }
      end

      context 'EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        it { should == _A("\xAC\x1A\x0C\x18" + value) }
      end

      context nil do
        let(:tag_class) { nil }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check nil
      end

      context :no_such_class do
        let(:tag_class) { :no_such_class }
        it { -> { subject }.should raise_error asn1error }
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
        let(:value) { 'こんにちは、世界！' }
        it { should == _A("\x0C\x18" + value) }
      end

      context 'custom tag' do
        let(:value) { 'こんにちは、世界！' }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == _A("\xCE\x18" + value) }
      end

      context 'tag_class' do
        let(:value) { 'こんにちは、世界！' }
        let(:tag_class) { :APPLICATION }
        it { should == _A("\x4C\x18" + value) }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { 'こんにちは、世界！' }
        let(:io) { string_io_object }
        its(:written_bytes) { should == _A("\x0C\x18" + value) }
      end

      context "Object responds to :write" do
        let(:value) { 'こんにちは、世界！' }
        let(:io) { writable_object }
        its(:written_bytes) { should == _A("\x0C\x18" + value) }
      end

      context "raise IO error transparently" do
        let(:value) { 'こんにちは、世界！' }
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new('こんにちは、世界！')
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'こんにちは、世界！' do
        let(:value) { 'こんにちは、世界！' }
        let(:der) { _A("\x0C\x18" + value) }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:value) { should == value }
      end

      context '(empty)' do
        let(:der) { "\x0C\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:value) { should == '' }
      end

      context '1000 octets' do
        let(:value) { 'あ' * 1000 }
        let(:der) { _A("\x0C\x82\x1F\x40" + value) }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:value) { should == value }
      end
    end

    context 'extracted tag class' do
      let(:value) { 'こんにちは、世界！' }

      context 'UNIVERSAL' do
        let(:der) { _A("\x0C\x18" + value) }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { _A("\x4C\x18" + value) }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { _A("\x8C\x18" + value) }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { _A("\xCC\x18" + value) }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { _A("\x0C\x18" + value) }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == _A("\x8C\x18" + value)
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { _A("\x0C\x18" + value) }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == _A("\xA0\x1A\x0C\x18" + value) 
        end
      end

    end
  end
end
