# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::Integer do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::Integer }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Integer
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

      context 'accepts Integer' do
        let(:value) { 72 }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 72 }
        its(:infinite_length) { should == false }
      end

      context 'accepts 0' do
        let(:value) { 0 }
        its(:value) { should == 0 }
      end

      context 'accepts negative Integer' do
        let(:value) { -72 }
        its(:value) { should == -72 }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new(72, tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::INTEGER }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new(72, Krypt::ASN1::INTEGER, tag_class) }

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
      subject { klass.new(true, Krypt::ASN1::INTEGER) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts Integer' do
        let(:value) { 72 }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 72 }
        its(:infinite_length) { should == false }
      end

      context 'accepts 0' do
        let(:value) { 0 }
        its(:value) { should == 0 }
      end

      context 'accepts negative Integer' do
        let(:value) { -72 }
        its(:value) { should == -72 }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::INTEGER }
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

      context 0 do
        let(:value) { 0 }
        it { should == "\x02\x01\x00" }
      end

      context 1 do
        let(:value) { 1 }
        it { should == "\x02\x01\x01" }
      end

      context -1 do
        let(:value) { -1 }
        it { should == "\x02\x01\xFF" }
      end

      context 72 do
        let(:value) { 72 }
        it { should == "\x02\x01\x48" }
      end

      context 127 do
        let(:value) { 127 }
        it { should == "\x02\x01\x7F" }
      end

      context -128 do
        let(:value) { -128 }
        it { should == "\x02\x01\x80" }
      end

      context 128 do
        let(:value) { 128 }
        it { should == "\x02\x02\x00\x80" }
      end

      context -27066 do
        let(:value) { -27066 }
        it { should == "\x02\x02\x96\x46" }
      end

      context 'max Fixnum on 32bit box' do
        let(:value) { 2**30-1 }
        it { should == "\x02\x04\x3F\xFF\xFF\xFF" }
      end

      context 'max Fixnum on 64bit box' do
        let(:value) { 2**62-1 }
        it { should == "\x02\x08\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF" }
      end

      context 'positive Bignum' do
        let(:value) { 2**12345 }
        it { should == "\x02\x82\x06\x08\x02" + "\x00" * 1543 }
      end

      context 'negative Bignum' do
        let(:value) { -(2**12345) }
        it { should == "\x02\x82\x06\x08\xFE" + "\x00" * 1543 }
      end

      context 'nil' do
        let(:value) { nil }
        it { expect { subject }.to raise_error asn1error } # TODO: ossl crashes
      end

      context 'String' do
        let(:value) { '123' }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    context 'rejects UNIVERSAL tags > 30' do
      it { expect { klass.new(1, 31, :UNIVERSAL).to_der }.to raise_error asn1error }
    end

    context 'encodes tag number' do
      subject { klass.new(72, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::INTEGER }
        it { should == "\xC2\x01\x48" }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == "\xCE\x01\x48" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      subject { klass.new(72, Krypt::ASN1::INTEGER, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x02\x01\x48" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x42\x01\x48" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x82\x01\x48" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC2\x01\x48" }
      end

      context 'accepts :IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        it { should == "\x82\x01\x48" }
      end

      context 'accepts :EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        it { should == "\xA2\x03\x02\x01\x48" }
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

      context 'value: 72' do
        let(:value) { 72 }
        it { should == "\x02\x01\x48" }
      end

      context 'custom tag' do
        let(:value) { 72 }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xCE\x01\x48" }
      end

      context 'tag_class' do
        let(:value) { 72 }
        let(:tag_class) { :APPLICATION }
        it { should == "\x42\x01\x48" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { 72 }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x02\x01\x48" }
      end

      context "Object responds to :write" do
        let(:value) { 72 }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x02\x01\x48" }
      end

      context "raise IO error transparently" do
        let(:value) { 72 }
        let(:io) { io_error_object }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new(72)
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 0 do
        let(:der) { "\x02\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 0 }
      end

      context 1 do
        let(:der) { "\x02\x01\x01" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 1 }
      end

      context -1 do
        let(:der) { "\x02\x01\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == -1 }
      end

      context 72 do
        let(:der) { "\x02\x01\x48" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 72 }
      end

      context 127 do
        let(:der) { "\x02\x01\x7F" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 127 }
      end

      context -128 do
        let(:der) { "\x02\x01\x80" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == -128 }
      end

      context 128 do
        let(:der) { "\x02\x02\x00\x80" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 128 }
      end

      context 256 do
        let(:der) { "\x02\x02\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 256 }
      end

      context -256 do
        let(:der) { "\x02\x02\xFF\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == -256 }
      end

      context -27066 do
        let(:der) { "\x02\x02\x96\x46" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == -27066 }
      end

      context 'max Fixnum on 32bit box' do
        let(:der) { "\x02\x04\x3F\xFF\xFF\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 2**30-1 }
      end

      context 'max Fixnum on 64bit box' do
        let(:der) { "\x02\x08\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 2**62-1 }
      end

      context 'positive Bignum' do
        let(:der) { "\x02\x82\x06\x08\x02" + "\x00" * 1543 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 2**12345 }
      end

      context 'negative Bignum' do
        let(:der) { "\x02\x82\x06\x08\xFE" + "\x00" * 1543 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == -(2**12345) }
      end

      context 'positive Bignum 4722366482869645213696' do
        let(:der) { "\x02\x0A\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 4722366482869645213696 }
      end

      context 'negative Bignum -4722366482869645213696' do
        let(:der) { "\x02\x0A\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == -4722366482869645213696 }
      end

      context 'positive Bignum 2361183241434822606593' do
        let(:der) { "\x02\x09\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x01" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == 2361183241434822606593 }
      end

      context 'negative Bignum -2361183241434822606593' do
        let(:der) { "\x02\x09\x80\x00\x00\x00\x00\x00\x00\x00\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        its(:value) { should == -(2361183241434822606593) }
      end

      context 'rejects zero length value' do
        let(:der) { "\x02\x00" }
        it { expect { subject.value }.to raise_error asn1error }
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x02\x01\x80" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x42\x01\x80" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x82\x01\x80" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC2\x01\x80" }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { "\x02\x01\x80" }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == "\x82\x01\x80"
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { "\x02\x01\x80" }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == "\xA0\x03\x02\x01\x80" 
        end
      end
    end
  end
end
