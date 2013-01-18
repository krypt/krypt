# encoding: US-ASCII

require 'rspec'
require 'krypt'
require_relative '../resources'

describe "Krypt::ASN1::Template::SequenceOf" do
  SEQ_OF = Krypt::ASN1::Template::SequenceOf
  let(:asn1error) { Krypt::ASN1::ASN1Error }
  
  context "extracted from parse_der" do
    subject { template.parse_der(der) }
    let(:template) do
      t = type
      Class.new do
        include SEQ_OF
        asn1_type t
      end
    end

    context "primitive contents" do
      let(:type) { Krypt::ASN1::Integer }
      let(:der) { "\x30\x06\x02\x01\x01\x02\x01\x01" }
      its(:value) { should be_an_instance_of Array }
      it { subject.value.size.should == 2 }
      it { subject.value.all? { |v| v.instance_of?(Krypt::ASN1::Integer) && v.value == 1 }.should == true }
      its(:to_der) { should == der }
    end

    context "template contents" do
      context "SEQUENCE" do
        let(:type) do
          Class.new do
            include Krypt::ASN1::Template::Sequence
            asn1_boolean :a
          end
        end
        let(:der) { "\x30\x0A\x30\x03\x01\x01\xFF\x30\x03\x01\x01\xFF" }
        its(:value) { should be_an_instance_of Array }
        it { subject.value.size.should == 2 }
        it { subject.value.all? { |v| v.instance_of?(type) && v.a == true }.should == true }
        its(:to_der) { should == der }
      end
      
      context "nested" do
        let(:type) do
          Class.new do
            include SEQ_OF
            asn1_type Krypt::ASN1::Integer
          end
        end
        let(:der) { "\x30\x0D\x30\x06\x02\x01\x01\x02\x01\x01\x30\x03\x02\x01\x02" }
        its(:value) { should be_an_instance_of Array }
        it { subject.value.size.should == 2 }
        it { subject.value[0].value.size.should == 2 }
        it { subject.value[0].value.all? { |v| v.instance_of?(Krypt::ASN1::Integer) && v.value == 1 }.should == true }
        it { subject.value[1].value.size.should == 1 }
        it { subject.value[1].value.all? { |v| v.instance_of?(Krypt::ASN1::Integer) && v.value == 2 }.should == true }
        its(:to_der) { should == der }
      end
    end
  end
end

