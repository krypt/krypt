# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::GeneralizedTime do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::GeneralizedTime }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::GeneralizedTime
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

      context 'accepts Time' do
        let(:value) { Time.now }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts Integer' do
        let(:value) { 0 + Time.now.to_i }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts String' do
        let(:value) { '' + Time.now.to_i.to_s }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts 0' do
        let(:value) { 0 }
        its(:value) { should == value }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new(Time.now, tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::GENERALIZED_TIME }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new(Time.now, Krypt::ASN1::GENERALIZED_TIME, tag_class) }

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
      subject { klass.new(Time.now, Krypt::ASN1::GENERALIZED_TIME) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts Time' do
        let(:value) { Time.now }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts Integer' do
        let(:value) { 0 + Time.now.to_i }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts String' do
        let(:value) { '' + Time.now.to_i.to_s }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts 0' do
        let(:value) { 0 }
        its(:value) { should == value }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::GENERALIZED_TIME }
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

      context 'Time' do
        let(:value) { Time.utc(2012, 1, 24, 0, 0, 0) }
        it { should == "\x18\x0F20120124000000Z" }
      end

      context 'Numeric' do
        let(:value) { Time.utc(2012, 1, 24, 0, 0, 0).to_i }
        it { should == "\x18\x0F20120124000000Z" }
      end

      context 'String' do
        let(:value) { Time.utc(2012, 1, 24, 0, 0, 0).to_i }
        it { should == "\x18\x0F20120124000000Z" }
      end

      context 'Min time representation' do
        let(:value) { Time.utc(2000, 1, 1, 0, 0, 0).to_i }
        it { should == "\x18\x0F20000101000000Z" }
      end

      context 'Max time representation' do
        let(:value) { Time.utc(1999, 12, 31, 23, 59, 59).to_i }
        it { should == "\x18\x0F19991231235959Z" }
      end

      context 'second fraction' do
        pending 'ossl does not support this'
      end

      context 'timezone' do
        pending 'ossl does not support this'
      end

      context '(empty)' do
        let(:value) { '' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'Bignum' do
        let(:value) { 2**64 - 1 }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'negative Integer' do
        let(:value) { -1 }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'String that Integer(str) barks' do
        let(:value) { "ABC" }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end
    end

    context 'encodes tag number' do
      subject { klass.new(1327330800, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::GENERALIZED_TIME }
        it { should == "\xD8\x0F20120123150000Z" }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == "\xCE\x0F20120123150000Z" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      subject { klass.new(1327330800, Krypt::ASN1::GENERALIZED_TIME, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x18\x0F20120123150000Z" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x58\x0F20120123150000Z" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x98\x0F20120123150000Z" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xD8\x0F20120123150000Z" }
      end

      context 'IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        it { should == "\x98\x0F20120123150000Z" }
      end

      context 'EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        it { should == "\xB8\x11\x18\x0F20120123150000Z" }
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

      context 'value: Time' do
        let(:value) { Time.utc(2012, 1, 24, 0, 0, 0) }
        it { should == "\x18\x0F20120124000000Z" }
      end

      context 'custom tag' do
        let(:value) {  Time.utc(2012, 1, 24, 0, 0, 0) }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xCE\x0F20120124000000Z" }
      end

      context 'tag_class' do
        let(:value) { Time.utc(2012, 1, 24, 0, 0, 0) }
        let(:tag_class) { :APPLICATION }
        it { should == "\x58\x0F20120124000000Z" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { 1327330800 }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x18\x0F20120123150000Z" }
      end

      context "Object responds to :write" do
        let(:value) { 1327330800 }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x18\x0F20120123150000Z" }
      end

      context "raise IO error transparently" do
        let(:value) { 1327330800 }
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new(1327330800)
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'Time' do
        let(:der) { "\x18\x0F20120124000000Z" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:value) { should == Time.utc(2012, 1, 24, 0, 0, 0) }
      end

      context 'with fraction' do
        pending 'ossl does not support this'
=begin
        let(:der) { "\x18\x1620120124000000.012345Z" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:value) { subject.usec.should == 12345 } # TODO: ossl does not support decoding usec
=end
      end

      context 'Min time representation' do
        let(:der) { "\x18\x0F20000101000000Z" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:value) { should == Time.utc(2000, 1, 1, 0, 0, 0) }
      end

      context 'Max time representation' do
        let(:der) { "\x18\x0F19991231235959Z" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
        its(:value) { should == Time.utc(1999, 12, 31, 23, 59, 59) }
      end

      context 'timezone' do
        context '+' do
          let(:der) { "\x18\x1320000101085959+0900" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
          pending 'No timezone support yet'
          its(:value) { Time.utc(1999, 12, 31, 23, 59, 59) }
        end

        context '-' do
          let(:der) { "\x18\x1319991231145959-0900" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
          pending 'No timezone support yet'
          its(:value) { Time.utc(1999, 12, 31, 23, 59, 59) }
        end

        context '+0' do
          let(:der) { "\x18\x1319991231235959+0000" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
          pending 'No timezone support yet'
          its(:value) { Time.utc(1999, 12, 31, 23, 59, 59) }
        end

        context '-0' do
          let(:der) { "\x18\x1319991231235959-0000" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::GENERALIZED_TIME }
          pending 'No timezone support yet'
          its(:value) { Time.utc(1999, 12, 31, 23, 59, 59) }
        end
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x18\x0F20120123150000Z" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x48\x0F20120123150000Z" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x98\x0F20120123150000Z" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC8\x0F20120123150000Z" }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { "\x18\x0F20120123150000Z" }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == "\x98\x0F20120123150000Z"
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { "\x18\x0F20120123150000Z" }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == "\xA0\x11\x18\x0F20120123150000Z" 
        end
      end
    end
  end
end
