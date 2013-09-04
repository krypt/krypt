# encoding: US-ASCII

require 'rspec'
require 'krypt'
require_relative '../resources'

describe "Krypt::ASN1::Template::Choice" do
  CHOICE = Krypt::ASN1::Template::Choice
  let(:asn1error) { Krypt::ASN1::ASN1Error }
  
  context "extracted from parse_der" do
    subject { template.parse_der(der) }

    context "single field" do
      let(:template) do
        Class.new do
          include CHOICE
          asn1_integer
        end
      end

      context "accepts correct encoding" do
        let(:der) { "\x02\x01\x01" }
        its(:value) { should == 1 }
        it { subject.type.should == Krypt::ASN1::INTEGER }
        it { subject.tag.should == Krypt::ASN1::INTEGER }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "rejects wrong encoding" do
        let(:der) { "\x04\x01\x01" }
        it { expect { subject.value }.to raise_error asn1error }
      end

      context "rejects encoding that is not complete" do
        let(:der) { "\x02\x01" }
        it { expect { subject.value }.to raise_error asn1error }
      end
    end

    context "two fields" do
      let(:template) do
        Class.new do
          include CHOICE
          asn1_integer
          asn1_boolean
        end
      end

      context "accepts correct encoding integer" do
        let(:der) { "\x02\x01\x01" }
        its(:value) { should == 1 }
        its(:type) { should == Krypt::ASN1::INTEGER }
        its(:tag) { should == Krypt::ASN1::INTEGER }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "accepts correct encoding boolean" do
        let(:der) { "\x01\x01\xFF" }
        its(:value) { should == true }
        its(:type) { should == Krypt::ASN1::BOOLEAN }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "rejects wrong encoding" do
        let(:der) { "\x04\x01\xFF" }
        it { expect { subject.value }.to raise_error asn1error }
      end
    end

    context "preserves non-DER encodings" do
      let(:template) do
        Class.new do
          include CHOICE
          asn1_boolean 
        end
      end
      let(:der) { "\x01\x83\x00\x00\x01\x22" }
      its(:to_der) { should == der }
    end

    context "does not choke on invalid encodings" do
      let(:template) do
        Class.new do
          include CHOICE
          asn1_integer
          asn1_octet_string
        end
      end

      context "when parsing them" do
        let(:der) { "\x02\x00" }
        it { expect { subject }.to_not raise_error }
      end

      context "and encodes them again exactly as received" do
        let(:der) { "\x02\x00" }
        its(:to_der) { should == der }
      end

      context "but raises an error when accessing the fields" do
        let(:der) { "\x02\x00" }
        it { expect { subject.value }.to raise_error asn1error }
      end

      context "but raises an error if the tag does not match" do
        let(:der) { "\x01\x01\xFF" }
        it { expect { subject.value }.to raise_error asn1error }
      end
    end

    context "with inner templates" do
      let(:template2) do
        Class.new do
          include Krypt::ASN1::Template::Sequence
          asn1_integer :a
        end
      end

      context "no further options" do
        let(:template) do
          t = template2
          Class.new do
            include CHOICE
            asn1_template t
          end
        end
        let(:der) { "\x30\x03\x02\x01\x01" }
        its(:value) { should be_an_instance_of template2 }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:type) { should == template2 }
        it { subject.value.a.should == 1 }
      end

      context "with implicit tags" do
        let(:template3) do
          Class.new do
            include Krypt::ASN1::Template::Sequence
            asn1_boolean :a
          end
        end
        let(:template) do
          t2 = template2
          t3 = template3
          Class.new do
            include CHOICE
            asn1_template t2, tag: 0, tagging: :IMPLICIT
            asn1_template t3, tag: 1, tagging: :IMPLICIT
          end
        end

        context "matches first" do
          let(:der) { "\xA0\x03\x02\x01\x01" }
          its(:value) { should be_an_instance_of template2 }
          its(:tag) { should == 0 }
          its(:type) { should == template2 }
          it { subject.value.a.should == 1 }
        end

        context "matches second" do
          let(:der) { "\xA1\x03\x01\x01\xFF" }
          its(:value) { should be_an_instance_of template3 }
          its(:tag) { should == 1 }
          its(:type) { should == template3 }
          it { subject.value.a.should == true }
        end
      end

      context "with explicit tags" do
        let(:template3) do
          Class.new do
            include Krypt::ASN1::Template::Sequence
            asn1_boolean :a
          end
        end
        let(:template) do
          t2 = template2
          t3 = template3
          Class.new do
            include CHOICE
            asn1_template t2, tag: 0, tagging: :EXPLICIT
            asn1_template t3, tag: 1, tagging: :EXPLICIT
          end
        end

        context "matches first" do
          let(:der) { "\xA0\x05\x30\x03\x02\x01\x01" }
          its(:value) { should be_an_instance_of template2 }
          its(:tag) { should == 0 }
          its(:type) { should == template2 }
          it { subject.value.a.should == 1 }
        end

        context "matches second" do
          let(:der) { "\xA1\x05\x30\x03\x01\x01\xFF" }
          its(:value) { should be_an_instance_of template3 }
          its(:tag) { should == 1 }
          its(:type) { should == template3 }
          it { subject.value.a.should == true }
        end
      end

      context "with SEQUENCE OF" do
        let(:template) do
          t2 = template2
          Class.new do
            include CHOICE
            asn1_sequence_of t2
          end
        end
        let(:der) { "\x30\x0A\x30\x03\x02\x01\x01\x30\x03\x02\x01\x01" }
        its(:value) { should be_an_instance_of Array }
        its(:type) { should == template2 }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        it { subject.value.size.should == 2 }
        it { subject.value.all? { |v| v.instance_of?(template2) && v.a == 1 }.should == true }
        its(:to_der) { should == der }
      end

      context "with SET OF" do
        let(:template) do
          t2 = template2
          Class.new do
            include CHOICE
            asn1_set_of t2
          end
        end
        let(:der) { "\x31\x0A\x30\x03\x02\x01\x01\x30\x03\x02\x01\x01" }
        its(:value) { should be_an_instance_of Array }
        its(:type) { should == template2 }
        its(:tag) { should == Krypt::ASN1::SET }
        it { subject.value.size.should == 2 }
        it { subject.value.all? { |v| v.instance_of?(template2) && v.a == 1 }.should == true }
        its(:to_der) { should == der }
      end

      context "with ANY" do
        context "alone" do
          let(:template) do
            t2 = template2
            Class.new do
              include CHOICE
              asn1_any
            end
          end
          let(:der) { "\x02\x01\x01" }
          its(:value) { should be_an_instance_of Krypt::ASN1::Integer }
          its(:type) { should == Krypt::ASN1::ASN1Data }
          its(:tag) { should == Krypt::ASN1::INTEGER }
          it { subject.value.value.should == 1 }
          its(:to_der) { should == der }
        end

        context "the first ANY field matches if no other will" do
          let(:template) do
            t2 = template2
            Class.new do
              include CHOICE
              asn1_integer
              asn1_any
            end
          end

          context "other matches" do
            let(:der) { "\x02\x01\x01" }
            its(:value) { should == 1 }
            its(:type) { should == Krypt::ASN1::INTEGER }
            its(:tag) { should == Krypt::ASN1::INTEGER }
            its(:to_der) { should == der }
          end

          context "ANY matches" do
            let(:der) { "\x01\x01\xFF" }
            its(:value) { should be_an_instance_of Krypt::ASN1::Boolean }
            its(:type) { should == Krypt::ASN1::ASN1Data }
            its(:tag) { should == Krypt::ASN1::BOOLEAN }
            it { subject.value.value.should == true }
            its(:to_der) { should == der }
          end
        end
      end
    end
  end
end

