# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::Sequence do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::Sequence }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Sequence
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

      context 'accepts SEQUENCE as Array' do
        let(:value) { [s('hello'), i(42), s('world')] }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts SEQUENCE OF as Array' do
        let(:value) { [s('hello'), s(','), s('world')] }
        its(:value) { should == value }
      end

      context 'accepts empty Array' do
        let(:value) { [] }
        its(:value) { should == [] }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      let(:value) { [s('hello')] }
      subject { klass.new(value, tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::SEQUENCE }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      let(:value) { [s('hello')] }
      subject { klass.new(value, Krypt::ASN1::SEQUENCE, tag_class) }

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
      subject { klass.new([s('hello')], Krypt::ASN1::SEQUENCE) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts SEQUENCE as Array' do
        let(:value) { [s('hello'), i(42), s('world')] }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts SEQUENCE OF as Array' do
        let(:value) { [s('hello'), s(','), s('world')] }
        its(:value) { should == value }
      end

      context 'accepts empty Array' do
        let(:value) { [] }
        its(:value) { should == [] }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::SEQUENCE }
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

    describe '#infinite_length' do
      subject { o = klass.new(nil); o.infinite_length = infinite_length; o }

      context 'accepts true' do
        let(:infinite_length) { true }
        its(:infinite_length) { should == true }
      end

      context 'accepts false' do
        let(:infinite_length) { false }
        its(:infinite_length) { should == false }
      end

      context 'accepts nil as false' do
        let(:infinite_length) { nil }
        its(:infinite_length) { should == false }
      end

      context 'accepts non boolean as true' do
        let(:infinite_length) { Object.new }
        its(:infinite_length) { should == true }
      end
    end
  end

  describe '#to_der' do
    context 'encodes a given value' do
      subject { klass.new(value).to_der }

      context 'SEQUENCE' do
        let(:value) { [s('hello'), i(42), s('world')] }
        it { should == "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context 'SEQUENCE OF OctetString' do
        let(:value) { [s(''), s(''), s('')] }
        it { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'SEQUENCE OF Integer' do
        let(:value) { [i(-1), i(0), i(1)] }
        it { should == "\x30\x09\x02\x01\xFF\x02\x01\x00\x02\x01\x01" }
      end

      context '(empty)' do
        let(:value) { [] }
        it { should == "\x30\x00" }
      end

      context '1000 elements' do
        let(:value) { [i(0)] * 1000 }
        it { should == "\x30\x82\x0B\xB8" + "\x02\x01\x00" * 1000 }
      end

      context 'responds to :each' do
        let(:value) {
          o = Object.new # TODO: Discuss - BasicObject does not support respond_to?
          def o.each
            yield Krypt::ASN1::OctetString.new('hello')
            yield Krypt::ASN1::Integer.new(42)
            yield Krypt::ASN1::OctetString.new('world')
          end
          o
        }
        it { should == "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context "keeps the ordering of the value in the encoding" do
        context "definite length Array" do
          let(:value) { [i(1), s("a"), Krypt::ASN1::Boolean.new(true)] }
          it { should == "\x30\x09\x02\x01\x01\x04\x01a\x01\x01\xFF" }
        end

        context "definite length Enumerable" do
          let(:value) {
            o = Object.new
            def o.each
              yield Krypt::ASN1::Integer.new(1)
              yield Krypt::ASN1::OctetString.new("a")
              yield Krypt::ASN1::Boolean.new(true)
            end
            o
          }
          it { should == "\x30\x09\x02\x01\x01\x04\x01a\x01\x01\xFF" }
        end

        context "infinite length" do
          subject { o = klass.new(value); o.infinite_length = true; o.to_der }

          context "infinite length Array" do
            let(:value) { [i(1), s("a"), Krypt::ASN1::Boolean.new(true)] }
            it { should == "\x30\x80\x02\x01\x01\x04\x01a\x01\x01\xFF\x00\x00" }
          end

          context "infinite length Enumerable" do
            let(:value) {
              o = Object.new
              def o.each
                yield Krypt::ASN1::Integer.new(1)
                yield Krypt::ASN1::OctetString.new("a")
                yield Krypt::ASN1::Boolean.new(true)
              end
              o
            }
            it { should == "\x30\x80\x02\x01\x01\x04\x01a\x01\x01\xFF\x00\x00" }
          end
        end
      end

      context 'nil' do
        let(:value) { nil }
        it { -> { subject }.should raise_error asn1error }
      end

      context 'does not respond to :each' do
        let(:value) { '123' }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag number' do
      let(:value) { [s(''), s(''), s('')] }
      subject { klass.new(value, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::SEQUENCE }
        it { should == "\xF0\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == "\xEE\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      let(:value) { [s(''), s(''), s('')] }
      subject { klass.new(value, Krypt::ASN1::SEQUENCE, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x70\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\xB0\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xF0\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        it { should == "\xB0\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        it { should == "\xB0\x08\x30\x06\x04\x00\x04\x00\x04\x00" }
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

    context 'encodes indefinite length packets' do
      subject {
        o = klass.new(nil, Krypt::ASN1::SEQUENCE, :UNIVERSAL)
        o.value = value if defined? value
        o.infinite_length = true
        o
      }

      context 'with EndOfContents' do
        let(:value) { [s('hello'), i(42), s('world'), eoc] }
        let(:infinite_length) { true }
        its(:to_der) { should == "\x30\x80\x04\x05hello\x02\x01\x2A\x04\x05world\x00\x00" }
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

      context 'value: SEQUENCE' do
        let(:value) { [s('hello'), i(42), s('world')] }
        it { should == "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context 'custom tag' do
        let(:value) { [s('hello'), i(42), s('world')] }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xEE\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context 'tag_class' do
        let(:value) { [s('hello'), i(42), s('world')] }
        let(:tag_class) { :APPLICATION }
        it { should == "\x70\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end
    end

    context "encodes infinite length values" do
      subject do
        asn1 = klass.new(value)
        asn1.infinite_length = true
        asn1.to_der
      end

      context "with explicit EOC" do
        let(:value) { [
          mod::Integer.new(1), 
          mod::Boolean.new(true), 
          mod::EndOfContents.new
        ] }
        it { subject.should == "\x30\x80\x02\x01\x01\x01\x01\xFF\x00\x00" }
      end

      context "without explicit EOC" do
        let(:value) { [
          mod::Integer.new(1), 
          mod::Boolean.new(true), 
        ] }
        it { subject.should == "\x30\x80\x02\x01\x01\x01\x01\xFF\x00\x00" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context "Object responds to :write" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context "raise IO error transparently" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    it 'returns self' do
      obj = klass.new([s(''), s(''), s('')])
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe '#each' do
    subject { yielded_value_from_each(klass.new(value)) }

    context "yields each value in its order" do
      let(:value) { [s('hello'), i(42), s('world')] }
      it { should == value }
    end

    context "yields nothing for empty value" do
      let(:value) { [] }
      it { should == value }
    end

    it "is Enumerable via each" do
      value = [s('hello'), i(42), s('world')]
      klass.new(value).map { |e| e.value }.should == ['hello', 42, 'world']
    end

    it "returns Enumerator for blockless call" do
      value = [s('hello'), i(42), s('world')]
      klass.new(value).each.next.value.should == 'hello'
    end

    it "yields each value for an Enumerable" do
      o = Object.new
      def o.each
        yield Krypt::ASN1::Integer.new(1)
        yield Krypt::ASN1::Integer.new(2)
        yield Krypt::ASN1::Integer.new(3)
      end
      klass.new(o).map { |e| e.value }.should == [1, 2, 3]
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'SEQUENCE' do
        let(:der) { "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        it 'contains decoded value' do
          value = subject.value
          value.size.should == 3
          value[0].value == 'hello'
          value[1].value == 42
          value[2].value == 'world'
        end
      end

      context 'SEQUENCE OF Integer' do
        let(:der) { "\x30\x0C\x02\x04\xFF\xFF\xFF\xFF\x02\x01\x00\x02\x01\x01" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        it 'contains decoded value' do
          value = subject.value
          value.size.should == 3
          value[0].value == -1
          value[1].value == 0
          value[2].value == 1
        end
      end

      context '(empty)' do
        let(:der) { "\x30\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:value) { should == [] }
      end

      context '1000 elements' do
        let(:der) { "\x30\x82\x0B\xB8" + "\x02\x01\x00" * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        it 'contains decoded value' do
          value = subject.value
          value.size == 1000
          value.all? { |v| v.value == 0 }.should be_true
        end
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x70\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\xB0\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xF0\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == "\xB0\x11\x04\x05hello\x02\x01\x2A\x04\x05world"
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == "\xA0\x13\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" 
        end
      end
    end

    context 'extracted infinite_length' do
      context 'definite encoding' do
        let(:der) { "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:infinite_length) { should be_false }
      end

      context 'indefinite encoding' do
        let(:der) { "\x30\x80\x04\x05hello\x02\x01\x2A\x04\x05world\x00\x00" }
        its(:infinite_length) { should be_true }
        it "drops EndOfContents as last value" do
          subject.value.size.should == 3
          subject.value.any? { |o| o.instance_of? Krypt::ASN1::EndOfContents }.should be_false
        end
      end
    end

    context "preserves the ordering present in the encoding" do
      context "definite length" do
        context "when immediately re-encoding" do
          let(:der) { "\x30\x08\x05\x00\x04\x01a\x02\x01\x01" }
          its(:to_der) { should == der }
        end
        
        context "when changing one of the values" do
          let(:der) { "\x30\x08\x05\x00\x04\x01a\x02\x01\x01" }
          it do
            subject.value[2].value = 5
            subject.to_der.should == "\x30\x08\x05\x00\x04\x01a\x02\x01\x05"
          end
        end
      end

      context "infinite length" do
        context "when immediately re-encoding" do
          let(:der) { "\x30\x80\x05\x00\x04\x01a\x02\x01\x01\x00\x00" }
          its(:to_der) { should == der }
        end
        
        context "when changing one of the values" do
          let(:der) { "\x30\x80\x05\x00\x04\x01a\x02\x01\x01\x00\x00" }
          it do
            subject.value[2].value = 5
            subject.to_der.should == "\x30\x80\x05\x00\x04\x01a\x02\x01\x05\x00\x00"
          end
        end
      end
    end
  end
end

