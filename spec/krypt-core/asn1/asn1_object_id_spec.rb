# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::ObjectId do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::ObjectId }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::ObjectId
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

      context 'accepts 1.0.8571.2' do
        let(:value) { '1.0.8571.2' }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == '1.0.8571.2' }
        its(:infinite_length) { should == false }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new('1.0.8571.2', tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::OBJECT_ID }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new('1.0.8571.2', Krypt::ASN1::OBJECT_ID, tag_class) }

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
      subject { klass.new('1.0.8571.2', Krypt::ASN1::OBJECT_ID) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts 1.0.8571.2' do
        let(:value) { '1.0.8571.2' }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == '1.0.8571.2' }
        its(:infinite_length) { should == false }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::OBJECT_ID }
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

      context '1.0.8571.2' do
        let(:value) { '1.0.8571.2' }
        it { should == "\x06\x04\x28\xC2\x7B\x02" }
      end

      context '(empty)' do
        let(:value) { '' }
        it { -> { subject }.should raise_error asn1error }
      end

      context '1' do
        let(:value) { '1' }
        it { -> { subject }.should raise_error asn1error }
      end

      # oid[0] ::= 0, 1, 2
      # oid[1] ::= 0, 1, 2, 3
      # v[0] ::= oid[0] * 40 + oid[1]
      context '2 octets optimization' do
        context '0.0' do
          let(:value) { '0.0' }
          it { should == "\x06\x01\x00" }
        end

        context '0.3' do
          let(:value) { '0.3' }
          it { should == "\x06\x01\x03" }
        end

        context '1.0' do
          let(:value) { '1.0' }
          it { should == "\x06\x01\x28" }
        end

        context '1.3' do
          let(:value) { '1.3' }
          it { should == "\x06\x01\x2B" }
        end
      end

      context '0.0.0.....0' do
        let(:value) { (['0'] * 999).join('.') }
        it { should == "\x06\x82\x03\xE6\x00" + "\x00" * 997 }
      end

      context '1.1.1.....1' do
        let(:value) { (['1'] * 1000).join('.') }
        it { should == "\x06\x82\x03\xE7\x29" + "\x01" * 998 }
      end

      context 'nil' do
        let(:value) { nil }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context '(empty)' do
        let(:value) { '' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'single octet' do
        let(:value) { '1' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'non OID format' do
        let(:value) { '1,0:1' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'non number id' do
        let(:value) { '1.0.ABC' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'starts with .' do
        let(:value) { '.0.8571.2' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'illegal first octet (must be 0..2)' do
        let(:value) { '3.0.8571.2' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'illegal second octet (must be 0..39)' do
        let(:value) { '1.40.8571.2' }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check value
      end

      context 'rejects sub identifiers in the bignum range' do
        let(:value) { "1.2." + "3" * 1000 + "4.5" }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag number' do
      subject { klass.new('1.0.8571.2', tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 6 }
        it { should == "\xC6\x04\x28\xC2\x7B\x02" }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == "\xCE\x04\x28\xC2\x7B\x02" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      subject { klass.new('1.0.8571.2', Krypt::ASN1::OBJECT_ID, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x06\x04\x28\xC2\x7B\x02" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x46\x04\x28\xC2\x7B\x02" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x86\x04\x28\xC2\x7B\x02" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC6\x04\x28\xC2\x7B\x02" }
      end

      context 'IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        it { should == "\x86\x04\x28\xC2\x7B\x02" }
      end

      context 'EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        it { should == "\xA6\x06\x06\x04\x28\xC2\x7B\x02" }
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

      context 'value: 1.0.8571.2' do
        let(:value) { '1.0.8571.2' }
        it { should == "\x06\x04\x28\xC2\x7B\x02" }
      end

      context 'custom tag' do
        let(:value) { '1.0.8571.2' }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xCE\x04\x28\xC2\x7B\x02" }
      end

      context 'tag_class' do
        let(:value) { '1.0.8571.2' }
        let(:tag_class) { :APPLICATION }
        it { should == "\x46\x04\x28\xC2\x7B\x02" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { '1.0.8571.2' }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x06\x04\x28\xC2\x7B\x02" }
      end

      context "Object responds to :write" do
        let(:value) { '1.0.8571.2' }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x06\x04\x28\xC2\x7B\x02" }
      end

      context "raise IO error transparently" do
        let(:value) { '1.0.8571.2' }
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new('1.0.8571.2')
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context '1.0.8571.2' do
        let(:der) { "\x06\x04\x28\xC2\x7B\x02" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:value) { should == '1.0.8571.2' }
      end

      context '2 octets optimization' do
        context '0.0' do
          let(:der) { "\x06\x01\x00" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '0.0' } # "ITU-T" in OpenSSL
        end

        context '0.3' do
          let(:der) { "\x06\x01\x03" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '0.3' }
        end

        context '1.0' do
          let(:der) { "\x06\x01\x28" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '1.0' } # "ISO" in OpenSSL
        end

        context '1.3' do
          let(:der) { "\x06\x01\x2B" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '1.3' } # "identified-organization" in OpenSSL
        end
      end

      context '0.0.0.....0' do
        let(:der) { "\x06\x82\x03\xE6\x00" + "\x00" * 997 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:value) { should == (['0'] * 999).join('.') }
      end

      context '1.1.1.....1' do
        let(:der) { "\x06\x82\x03\xE7\x29" + "\x01" * 998 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:value) { should == (['1'] * 1000).join('.') }
      end

      context 'Illegal first octet too large (3.50.2.3)' do
        let(:der) { "\x06\x03\xAA\x02\x03" }
        it { -> { subject.value }.should raise_error asn1error }
      end

      context 'Illegal first sub id (4.2.0.0)' do
        let(:der) { "\x06\x03\xA2\x00\x00" }
        it { -> { subject.value }.should raise_error asn1error }
      end
      
      describe 'We cannot prevent this mistake, so the parsed value will be different than expected' do
        context 'Illegal second sub id (1.40.0.0)' do
          let(:der) { "\x06\x03\x50\x00\x00" }
          its(:value) { should == "2.0.0.0" }
        end
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x06\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x46\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x86\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC6\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { "\x06\x04\x28\xC2\x7B\x02" }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == "\x86\x04\x28\xC2\x7B\x02"
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { "\x06\x04\x28\xC2\x7B\x02" }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == "\xA0\x06\x06\x04\x28\xC2\x7B\x02" 
        end
      end
    end
  end
end
