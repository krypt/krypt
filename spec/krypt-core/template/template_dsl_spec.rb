# encoding: US-ASCII

require 'rspec'
require 'krypt'
require_relative '../resources'


shared_examples_for "a primitive declaration" do |func|
  let(:asn1error) { Krypt::ASN1::ASN1Error }
  subject do
    n = name
    o = opts
    c = Class.new do
      include Krypt::ASN1::Template::Sequence
        send(func, n, o)
    end
    c.new
  end

  context "rejects declaration with no name" do
    let(:name) { nil }
    let(:opts) { nil }
    specify { expect { subject }.to raise_error ArgumentError }
  end

  context "declararation with no options" do
    let(:name) { :test }
    let(:opts) { nil }
    specify { subject.should respond_to name }
  end

  context "declaration with options" do
    let(:name) { :test }

    context "allows to mark as optional" do
      let(:opts) { {optional: true} }
      specify { subject.should respond_to name }
    end

    context "allows to set a tag" do
      let(:opts) { {tag: 42} }
      specify { subject.should respond_to name }
    end

    context "allows to set tagging" do
      let(:opts) { {tagging: :EXPLICIT} }
      specify { subject.should respond_to name }
    end

    context "allows to set tagging" do
      let(:opts) { {tagging: :EXPLICIT} }
      specify { subject.should respond_to name }
    end

    context "allows to set arbitrary default value" do
      let(:opts) { {default: Object.new} }
      specify { subject.should respond_to name }
    end

    context "allows to set optional, tag, tagging and default at once" do
      let(:opts) { {optional: true, tag: 42, tagging: :IMPLICIT, default: Object.new} }
      specify { subject.should respond_to name }
    end
  end
end

shared_examples_for "a typed declaration" do |func|
  let(:template) do
    Class.new do
      include Krypt::ASN1::Template::Sequence
      asn1_integer :version
    end
  end

  subject do
    n = name
    t = type
    o = opts
    c = Class.new do
      include Krypt::ASN1::Template::Sequence
      send(func, n, t, o)
    end
    c.new
  end

  context "rejects declaration with no name" do
    let(:name) { nil }
    let(:type) { template }
    let(:opts) { nil }
    specify { expect { subject }.to raise_error ArgumentError }
  end

  context "rejects declaration with no type" do
    let(:name) { :test }
    let(:type) { nil }
    let(:opts) { nil }
    specify { expect { subject }.to raise_error ArgumentError }
  end

  context "declararation with no options" do
    let(:name) { :test }
    let(:type) { template }
    let(:opts) { nil }
    specify { subject.should respond_to name }
  end

  context "declaration with options" do
    let(:name) { :test }
    let(:type) { template }

    context "allows to mark as optional" do
      let(:opts) { {optional: true} }
      specify { subject.should respond_to name }
    end

    context "allows to set a tag" do
      let(:opts) { {tag: 42} }
      specify { subject.should respond_to name }
    end

    context "allows to set tagging" do
      let(:opts) { {tagging: :EXPLICIT} }
      specify { subject.should respond_to name }
    end

    context "allows to set tagging" do
      let(:opts) { {tagging: :EXPLICIT} }
      specify { subject.should respond_to name }
    end

    context "allows to set arbitrary default value" do
      let(:opts) { {default: Object.new} }
      specify { subject.should respond_to name }
    end

    context "allows to set optional, tag, tagging and default at once" do
      let(:opts) { {optional: true, tag: 42, tagging: :IMPLICIT, default: Object.new} }
      specify { subject.should respond_to name }
    end
  end
end

shared_examples_for "Krypt::ASN1::Template" do
  context "inclusion enables a set of DSL class methods" do
    context("asn1_boolean")          { it_behaves_like "a primitive declaration", :asn1_boolean }
    context("asn1_integer")          { it_behaves_like "a primitive declaration", :asn1_integer } 
    context("asn1_bit_string")       { it_behaves_like "a primitive declaration", :asn1_bit_string }
    context("asn1_octet_string")     { it_behaves_like "a primitive declaration", :asn1_octet_string }
    context("asn1_null")             { it_behaves_like "a primitive declaration", :asn1_null }
    context("asn1_object_id")        { it_behaves_like "a primitive declaration", :asn1_object_id }
    context("asn1_enumerated")       { it_behaves_like "a primitive declaration", :asn1_enumerated }
    context("asn1_utf8_string")      { it_behaves_like "a primitive declaration", :asn1_utf8_string }
    context("asn1_numeric_string")   { it_behaves_like "a primitive declaration", :asn1_numeric_string }
    context("asn1_printable_string") { it_behaves_like "a primitive declaration", :asn1_printable_string }
    context("asn1_t61_string")       { it_behaves_like "a primitive declaration", :asn1_t61_string }
    context("asn1_videotex_string")  { it_behaves_like "a primitive declaration", :asn1_videotex_string }
    context("asn1_ia5_string")       { it_behaves_like "a primitive declaration", :asn1_ia5_string }
    context("asn1_utc_time")         { it_behaves_like "a primitive declaration", :asn1_utc_time }
    context("asn1_generalized_time") { it_behaves_like "a primitive declaration", :asn1_generalized_time }
    context("asn1_graphic_string")   { it_behaves_like "a primitive declaration", :asn1_graphic_string }
    context("asn1_iso64_string")     { it_behaves_like "a primitive declaration", :asn1_iso64_string }
    context("asn1_general_string")   { it_behaves_like "a primitive declaration", :asn1_general_string }
    context("asn1_universal_string") { it_behaves_like "a primitive declaration", :asn1_universal_string }
    context("asn1_bmp_string")       { it_behaves_like "a primitive declaration", :asn1_bmp_string }
    context("asn1_any")              { it_behaves_like "a primitive declaration", :asn1_any }

    context("asn1_template")         { it_behaves_like "a typed declaration",     :asn1_template }
    context("asn1_sequence_of")      { it_behaves_like "a typed declaration",     :asn1_sequence_of }
    context("asn1_set_of")           { it_behaves_like "a typed declaration",     :asn1_set_of }
  end
end

shared_examples_for "constructed type constructor" do |type|
  let (:template) do
    Class.new do
      include type
      asn1_integer :a
    end
  end

  it "takes no-args" do
    template.new.should be_an_instance_of template
  end

  it "takes a block and yields the new instance" do
    template.new do |o|
      o.should be_an_instance_of template
    end
  end

  it "allows assignment to its fields once instantiated" do
    o = template.new
    o.a = 42
    o.a.should == 42
  end

  it "allows assignment to its fields inside the block" do
    obj = template.new do |o|
      o.a = 42
    end
    obj.a.should == 42
  end
end
      
shared_examples_for "DER-based equality with <=>" do |type|
  let(:template) do
    t = type
    Class.new do
      include t
      asn1_integer :a
    end
  end

  let(:tag) do
    if type == Krypt::ASN1::Template::Sequence
      "\x30"
    elsif type == Krypt::ASN1::Template::Set
      "\x31"
    else
      raise "only Set or Sequence"
    end
  end

  context "determines equality based on the encoding" do
    let(:der) { "#{tag}\x03\x02\x01\x01" }
    let(:v1) { template.parse_der(der) }
    let(:v2) { template.parse_der(der) }
    specify { v1.should == v2 && v1.eql?(v2).should == false }
  end

  context "finds a value encoded and reparsed to be equal to itself" do
    let(:v1) { template.parse_der("#{tag}\x03\x02\x01\x01") }
    specify { v1.should == (template.parse_der(v1.to_der)) }
  end

  context "when equal in terms of DER but not BER" do
    let(:v1) { template.parse_der("#{tag}\x83\x00\x00\x03\x02\x01\x01") }
    let(:v2) { template.parse_der("#{tag}\x03\x02\x01\x01") }
    specify { v1.should_not == v2 }
  end
end

shared_examples_for "accepting fields with special name" do |type, name|
  let(:template) do
    t = type
    n = name
    Class.new do
      include t
      asn1_integer name
    end
  end

  let(:tag) do
    if type == Krypt::ASN1::Template::Sequence
      "\x30"
    elsif type == Krypt::ASN1::Template::Set
      "\x31"
    else
      raise "only Set or Sequence"
    end
  end

  context "allows getting the value from a fresh instance" do
    subject { template.new }
    specify { subject.send(name).should be_nil }
  end

  context "allows getting the value from a parsed instance" do
    subject { template.parse_der("#{tag}\x03\x02\x01\x01") }
    specify { subject.send(name).should eq(1) }
  end

  context "allows setting the value on a fresh instance" do
    subject { template.new }
    specify { subject.send("#{name}=".to_sym, 2).should eq(2) }
  end

  context "allows setting the value on a parsed instance" do
    subject { template.parse_der("#{tag}\x03\x02\x01\x01") }
    specify do
      obj = subject
      obj.send(name).should eq(1)
      obj.send("#{name}=".to_sym, 2).should eq(2)
      obj.send(name).should eq(2)
    end
  end
end

describe "Krypt::ASN1::Template::Sequence" do
  it_behaves_like "Krypt::ASN1::Template"
  it_behaves_like "constructed type constructor", Krypt::ASN1::Template::Sequence
  it_behaves_like "DER-based equality with <=>", Krypt::ASN1::Template::Sequence
  it_behaves_like "accepting fields with special name", Krypt::ASN1::Template::Sequence, :tag
  it_behaves_like "accepting fields with special name", Krypt::ASN1::Template::Sequence, :type
end

describe "Krypt::ASN1::Template::Set" do
  it_behaves_like "Krypt::ASN1::Template"
  it_behaves_like "constructed type constructor", Krypt::ASN1::Template::Set
  it_behaves_like "DER-based equality with <=>", Krypt::ASN1::Template::Set
  it_behaves_like "accepting fields with special name", Krypt::ASN1::Template::Set, :tag
  it_behaves_like "accepting fields with special name", Krypt::ASN1::Template::Set, :type
end

describe "Krypt::ASN1::Template::Choice" do
  let (:template) do
    Class.new do
      include Krypt::ASN1::Template::Choice
      asn1_integer 
      asn1_boolean
    end
  end

  describe "#new" do
    it "takes no-args" do
      template.new.should be_an_instance_of template
    end

    it "takes a block and yields the new instance" do
      template.new do |o|
        o.should be_an_instance_of template
      end
    end

    it "allows assignment to 'value' once instantiated" do
      o = template.new
      o.value = 42
      o.value.should == 42 
    end

    it "allows assignment to 'type' once instantiated" do
      o = template.new
      o.type = Krypt::ASN1::INTEGER
      o.type.should == Krypt::ASN1::INTEGER
    end

    it "allows assignment to 'tag' once instantiated" do
      o = template.new
      o.tag = Krypt::ASN1::INTEGER
      o.tag.should == Krypt::ASN1::INTEGER
    end

    it "allows assignment to 'value' inside the block" do
      obj = template.new do |o|
        o.value = 42
      end
      obj.value.should == 42 
    end
  end
end

