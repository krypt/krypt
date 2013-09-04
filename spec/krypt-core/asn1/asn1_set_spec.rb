# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::Set do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::Set }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Set
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

      context 'accepts SET as Array' do
        let(:value) { [s('hello'), i(42), s('world')] }
        its(:tag) { should == Krypt::ASN1::SET }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts SET OF as Array' do
        let(:value) { [s('hello'), s(','), s('world')] }
        its(:tag) { should == Krypt::ASN1::SET }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
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
        let(:tag) { Krypt::ASN1::SET }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      let(:value) { [s('hello')] }
      subject { klass.new(value, Krypt::ASN1::SET, tag_class) }

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
      subject { klass.new([s('hello')], Krypt::ASN1::SET) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts SET as Array' do
        let(:value) { [s('hello'), i(42), s('world')] }
        its(:tag) { should == Krypt::ASN1::SET }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts SET OF as Array' do
        let(:value) { [s('hello'), s(','), s('world')] }
        its(:tag) { should == Krypt::ASN1::SET }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts empty Array' do
        let(:value) { [] }
        its(:value) { should == [] }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::SET }
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

      context 'SET' do
        let(:value) { [s('hello'), i(42), s('world')] }
        it { should == "\x31\x11\x02\x01\x2A\x04\x05hello\x04\x05world" }
      end

      context 'SET OF OctetString' do
        let(:value) { [s(''), s(''), s('')] }
        it { should == "\x31\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'SET OF Integer' do
        let(:value) { [i(-1), i(0), i(1)] }
        it { should == "\x31\x09\x02\x01\x00\x02\x01\x01\x02\x01\xFF" }
      end

      context '(empty)' do
        let(:value) { [] }
        it { should == "\x31\x00" }
      end

      context '1000 elements' do
        let(:value) { [i(0)] * 1000 }
        it { should == "\x31\x82\x0B\xB8" + "\x02\x01\x00" * 1000 }
      end

      context 'responds to :each and to sort' do
        let(:value) {
          o = Object.new
          def o.each
            yield Krypt::ASN1::OctetString.new('hello')
            yield Krypt::ASN1::Integer.new(42)
            yield Krypt::ASN1::OctetString.new('world')
          end
          def o.sort
            [
              Krypt::ASN1::OctetString.new('hello'),
              Krypt::ASN1::Integer.new(42),
              Krypt::ASN1::OctetString.new('world')
            ].sort
          end
          o
        }
        it { should == "\x31\x11\x02\x01\x2A\x04\x05hello\x04\x05world" }
      end

      context 'responds to :each, but not sortable' do
        let(:value) {
          o = Object.new
          def o.each
            yield Krypt::ASN1::OctetString.new('hello')
            yield Krypt::ASN1::Integer.new(42)
            yield Krypt::ASN1::OctetString.new('world')
          end
          o
        }
        it { should == "\x31\x11\x02\x01\x2A\x04\x05hello\x04\x05world" }
      end

      context "orders SET encoding by tag when creating the SET" do
        context "definite length Array" do
          let (:value) { [ 
            Krypt::ASN1::Null.new,
            Krypt::ASN1::Integer.new(1),
            Krypt::ASN1::Boolean.new(true)
          ] }
          it { should == "\x31\x08\x01\x01\xFF\x02\x01\x01\x05\x00" }
        end

        context "definite length Enumerable" do
          let(:value) {
            o = Object.new
            def o.each
              yield Krypt::ASN1::Null.new
              yield Krypt::ASN1::Integer.new(1)
              yield Krypt::ASN1::Boolean.new(true)
            end
            o
          }
          it { should == "\x31\x08\x01\x01\xFF\x02\x01\x01\x05\x00" }
        end

        context "infinite length" do
          subject { o = klass.new(value); o.infinite_length = true; o.to_der } 

          context "infinite length Array" do
            let (:value) { [ 
              Krypt::ASN1::Null.new,
              Krypt::ASN1::Integer.new(1),
              Krypt::ASN1::Boolean.new(true)
            ] }
            it { should == "\x31\x80\x01\x01\xFF\x02\x01\x01\x05\x00\x00\x00" }
          end

          context "infinite length Enumerable" do
            let(:value) {
              o = Object.new
              def o.each
                yield Krypt::ASN1::Null.new
                yield Krypt::ASN1::Integer.new(1)
                yield Krypt::ASN1::Boolean.new(true)
              end
              o
            }
            it { should == "\x31\x80\x01\x01\xFF\x02\x01\x01\x05\x00\x00\x00" }
          end
        end
      end

      context "orders SET OF encoding in lexicographical order when creating the SET" do
        context "definite length Array" do
          let (:value) { [ 
            Krypt::ASN1::OctetString.new("aaaaaa"),
            Krypt::ASN1::OctetString.new("aaaab"),
            Krypt::ASN1::OctetString.new("aaa"),
            Krypt::ASN1::OctetString.new("b")
          ] }
          it { should == "\x31\x17\x04\x01b\x04\x03aaa\x04\x05aaaab\x04\x06aaaaaa" }
        end

        context "definite length Enumerable" do
          let (:value) {
            o = Object.new
            def o.each
              yield Krypt::ASN1::OctetString.new("aaaaaa")
              yield Krypt::ASN1::OctetString.new("aaaab")
              yield Krypt::ASN1::OctetString.new("aaa")
              yield Krypt::ASN1::OctetString.new("b")
            end
            o
          }
          it { should == "\x31\x17\x04\x01b\x04\x03aaa\x04\x05aaaab\x04\x06aaaaaa" }
        end

        context "infinite length" do
          subject { o = klass.new(value); o.infinite_length = true; o.to_der } 

          context "Array" do
            let (:value) { [ 
              Krypt::ASN1::OctetString.new("aaaaaa"),
              Krypt::ASN1::OctetString.new("aaaab"),
              Krypt::ASN1::OctetString.new("aaa"),
              Krypt::ASN1::OctetString.new("b")
            ] }
            it { should == "\x31\x80\x04\x01b\x04\x03aaa\x04\x05aaaab\x04\x06aaaaaa\x00\x00" }
          end

          context "Enumerable" do
            let (:value) {
              o = Object.new
              def o.each
                yield Krypt::ASN1::OctetString.new("aaaaaa")
                yield Krypt::ASN1::OctetString.new("aaaab")
                yield Krypt::ASN1::OctetString.new("aaa")
                yield Krypt::ASN1::OctetString.new("b")
              end
              o
            }
            it { should == "\x31\x80\x04\x01b\x04\x03aaa\x04\x05aaaab\x04\x06aaaaaa\x00\x00" }
          end
        end
      end

      context 'nil' do
        let(:value) { nil }
        it { expect { subject }.to raise_error asn1error }
      end

      context 'does not respond to :each' do
        let(:value) { '123' }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    context 'encodes tag number' do
      let(:value) { [s(''), s(''), s('')] }
      subject { klass.new(value, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::SET }
        it { should == "\xF1\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'custom tag' do
        let(:tag) { 14 }
        it { should == "\xEE\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { expect { subject }.to raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      let(:value) { [s(''), s(''), s('')] }
      subject { klass.new(value, Krypt::ASN1::SET, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x31\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x71\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\xB1\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xF1\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'IMPLICIT' do
        let(:tag_class) { :IMPLICIT }
        it { should == "\xB1\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'EXPLICIT' do
        let(:tag_class) { :EXPLICIT }
        it { should == "\xB1\x08\x31\x06\x04\x00\x04\x00\x04\x00" }
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

    context 'encodes indefinite length packets' do
      subject {
        o = klass.new(nil, Krypt::ASN1::SET, :UNIVERSAL)
        o.value = value if defined? value
        o.infinite_length = true
        o
      }

      context 'with EndOfContents' do
        let(:value) { [s('hello'), i(42), s('world'), eoc] }
        let(:infinite_length) { true }
        its(:to_der) { should == "\x31\x80\x02\x01\x2A\x04\x05hello\x04\x05world\x00\x00" }
      end

      context 'with 0-tagged zero-length value without EndOfContents' do
        let(:value) { [i(0), i(-1), Krypt::ASN1::ASN1Data.new(nil, 0, :CONTEXT_SPECIFIC)] }
        let(:infinite_length) { true }
        its(:to_der) { should == "\x31\x80\x80\x00\x02\x01\x00\x02\x01\xFF\x00\x00" }
      end

      context 'with 0-tagged zero-length value with EndOfContents' do
        let(:value) { [i(0), i(-1), Krypt::ASN1::ASN1Data.new(nil, 0, :CONTEXT_SPECIFIC), Krypt::ASN1::EndOfContents.new] }
        let(:infinite_length) { true }
        its(:to_der) { should == "\x31\x80\x80\x00\x02\x01\x00\x02\x01\xFF\x00\x00" }
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

      context 'value: SET' do
        let(:value) { [s('hello'), i(42), s('world')] }
        it { should == "\x31\x11\x02\x01\x2A\x04\x05hello\x04\x05world" }
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
        it { should == "\x71\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
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
        it { subject.should == "\x31\x80\x01\x01\xFF\x02\x01\x01\x00\x00" }
      end

      context "without explicit EOC" do
        let(:value) { [
          mod::Integer.new(1), 
          mod::Boolean.new(true), 
        ] }
        it { subject.should == "\x31\x80\x01\x01\xFF\x02\x01\x01\x00\x00" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x31\x06\x04\x00\x04\x00\x04\x00" }
      end

      context "Object responds to :write" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x31\x06\x04\x00\x04\x00\x04\x00" }
      end

      context "raise IO error transparently" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { io_error_object }
        it { expect { subject }.to raise_error asn1error }
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
      context 'SET' do
        let(:der) { "\x31\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SET }
        it 'contains decoded value' do
          value = subject.value
          value.size.should == 3
          value[0].value == 'hello'
          value[1].value == 42
          value[2].value == 'world'
        end
      end

      context 'SET OF Integer' do
        let(:der) { "\x31\x0C\x02\x04\xFF\xFF\xFF\xFF\x02\x01\x00\x02\x01\x01" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SET }
        it 'contains decoded value' do
          value = subject.value
          value.size.should == 3
          value[0].value == -1
          value[1].value == 0
          value[2].value == 1
        end
      end

      context '(empty)' do
        let(:der) { "\x31\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SET }
        its(:value) { should == [] }
      end

      context '1000 elements' do
        let(:der) { "\x31\x82\x0B\xB8" + "\x02\x01\x00" * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SET }
        it 'contains decoded value' do
          value = subject.value
          value.size == 1000
          value.all? { |v| v.value == 0 }.should be_true
        end
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x31\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x71\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\xB1\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xF1\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :PRIVATE }
      end

      context "setting IMPLICIT will result in CONTEXT_SPECIFIC" do
        let(:der) { "\x31\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        it do
          subject.tag_class = :IMPLICIT
          subject.to_der.should == "\xB1\x11\x04\x05hello\x02\x01\x2A\x04\x05world"
        end
      end

      context "setting EXPLICIT will reencode as CONTEXT_SPECIFIC" do
        let(:der) { "\x31\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        it do
          subject.tag_class = :EXPLICIT
          subject.tag = 0
          subject.to_der.should == "\xA0\x13\x31\x11\x02\x01\x2A\x04\x05hello\x04\x05world" 
        end
      end
    end

    context "preserves wrongly encoded SET encodings" do
      context "definite length" do
        let(:der) { "\x31\x08\x05\x00\x02\x01\x01\x01\x01\xFF" }
        it do
          ary = subject.value
          ary.size.should == 3
          ary[0].tag.should == Krypt::ASN1::NULL
          ary[1].tag.should == Krypt::ASN1::INTEGER
          ary[2].tag.should == Krypt::ASN1::BOOLEAN
          subject.to_der.should == der
        end
      end

      context "infinite length" do
        let(:der) { "\x31\x80\x05\x00\x02\x01\x01\x01\x01\xFF\x00\x00" }
        it do
          ary = subject.value
          ary.size.should == 3
          ary[0].tag.should == Krypt::ASN1::NULL
          ary[1].tag.should == Krypt::ASN1::INTEGER
          ary[2].tag.should == Krypt::ASN1::BOOLEAN
          subject.to_der.should == der
        end
      end

      context "reencodes the value in proper SET encoding when the set value is changed" do
        let(:der) { "\x31\x08\x05\x00\x02\x01\x01\x01\x01\xFF" }
        it do
          subject.value = [
            Krypt::ASN1::Null.new,
            Krypt::ASN1::Integer.new(1),
            Krypt::ASN1::Boolean.new(true)
          ]
          subject.to_der.should == "\x31\x08\x01\x01\xFF\x02\x01\x01\x05\x00"
        end
      end

      context "keeps the wrong SET order when an inner value is changed" do # would be too expensive to track
        let(:der) { "\x31\x08\x05\x00\x02\x01\x01\x01\x01\xFF" }
        it do
          ary = subject.value
          ary[1].value = 7
          subject.to_der.should == "\x31\x08\x05\x00\x02\x01\x07\x01\x01\xFF"
        end
      end
    end

    context "preserves wrongly encoded SET OF encodings" do
      context "definite length" do
        let(:der) { "\x31\x0C\x04\x01b\x04\x03aaa\x04\x02aa" }
        it do
          ary = subject.value
          ary.size.should == 3
          ary[0].value.should == "b"
          ary[1].value.should == "aaa"
          ary[2].value.should == "aa"
          subject.to_der.should == der
        end
      end

      context "infinite length" do
        let(:der) { "\x31\x80\x04\x01b\x04\x03aaa\x04\x02aa\x00\x00" }
        it do
          ary = subject.value
          ary.size.should == 3
          ary[0].value.should == "b"
          ary[1].value.should == "aaa"
          ary[2].value.should == "aa"
          subject.to_der.should == der
        end
      end

      context "reencodes the value in proper SET OF encoding when the set value is changed" do
        let(:der) { "\x31\x0C\x04\x01b\x04\x03aaa\x04\x02aa" }
        it do
          subject.value = subject.value
          subject.to_der.should == "\x31\x0C\x04\x01b\x04\x02aa\x04\x03aaa"
        end
      end

      context "keeps the wrong SET order when an inner value is changed" do # would be too expensive to track
        let(:der) { "\x31\x0C\x04\x01b\x04\x03aaa\x04\x02aa" }
        it do
          ary = subject.value
          ary[0].value = "c"
          subject.to_der.should == "\x31\x0C\x04\x01c\x04\x03aaa\x04\x02aa"
        end
      end
    end

    context 'extracted infinite_length' do
      context 'definite encoding' do
        let(:der) { "\x31\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:infinite_length) { should == false }
      end

      context 'indefinite encoding' do
        let(:der) { "\x31\x80\x04\x05hello\x02\x01\x2A\x04\x05world\x00\x00" }
        its(:infinite_length) { should == true }
        it "drops EndOfContents as last value" do
          subject.value.size.should == 3
          subject.value.any? { |o| o.instance_of? Krypt::ASN1::EndOfContents }.should be_false
        end
      end
    end
  end
end

