# encoding: US-ASCII

require 'rspec'
require 'krypt'
require_relative '../resources'


describe "Krypt::ASN1::Template::Sequence" do
  SEQ = Krypt::ASN1::Template::Sequence
  let(:asn1error) { Krypt::ASN1::ASN1Error }
  
  context "extracted from parse_der" do
    subject { template.parse_der(der) }

    context "single field" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :version
        end
      end
      context "accepts correct encoding" do
        let(:der) { "\x30\x03\x02\x01\x01" }
        its(:version) { should == 1 }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
      context "rejects wrong encoding" do
        let(:der) { "\x30\x03\x04\x01\x01" }
        it { expect { subject.version }.to raise_error asn1error }
      end
      context "rejects encoding that is too long" do
        let(:der) { "\x30\x06\x04\x01\x01\x04\x01\x01" }
        it { expect { subject.version }.to raise_error asn1error }
      end
      context "rejects encoding that is not complete" do
        let(:der) { "\x30\x03\x04\x01" }
        it { expect { subject.version }.to raise_error asn1error }
      end
    end

    context "two fields" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :version
          asn1_boolean :works?
        end
      end
      context "accepts correct encoding" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:version) { should == 1 }
        its(:works?) { should == true }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
      context "rejects encodings where either field is missing" do
        context "(first)" do
          let(:der) { "\x30\x03\x01\x01\xFF" }
          it { expect { subject.version }.to raise_error asn1error }
        end
        context "(second)" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          it { expect { subject.version }.to raise_error asn1error }
        end
      end
    end

    context "preserves non-DER encodings" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_boolean :a
          asn1_octet_string :b
        end
      end
      let(:der) { "\x30\x83\x00\x00\x0D\x01\x01\xBB\x24\x80\x04\x01\x01\x04\x01\x02\x00\x00" }
      its(:to_der) { should == der }
    end

    context "does not choke on invalid encodings" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_octet_string :b
        end
      end

      context "when parsing them" do
        let(:der) { "\x30\x04\x00\x00\x22\x99" }
        it { expect { subject }.to_not raise_error }
      end

      context "and encodes them again exactly as received" do
        let(:der) { "\x30\x04\x00\x00\x22\x99" }
        its(:to_der) { should == der }
      end

      context "but raises an error when accessing the fields" do
        let(:der) { "\x30\x04\x00\x00\x22\x99" }
        it { expect { subject.a }.to raise_error asn1error }
      end

      context "but raises an error if the tag doesn't match" do
        let(:der) { "\x31\x06\x02\x01\x01\x04\x01a" }
        it { expect { subject.a }.to raise_error asn1error }
      end
    end

    context "tagged field" do
      let(:template) do
        t = tag
        tg = tagging
        Class.new do
          include SEQ
          asn1_integer :a, tag: t, tagging: tg 
          asn1_boolean :b
        end
      end

      shared_examples_for "a non-constructed encoding" do |tagging, tag_byte|
        context "accepts correct encoding" do
          let(:der) { "\x30\x06#{tag_byte}\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { tagging }
          its(:a) { should == 1 }
          its(:b) { should == true }
          its(:to_der) { should == der }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { tagging }
          it { expect { subject.a }.to raise_error asn1error }
        end
      end

      context ":IMPLICIT" do
        it_behaves_like "a non-constructed encoding", :IMPLICIT, "\x80"
      end

      context ":EXPLICIT" do
        context "accepts correct encoding" do
          let(:der) { "\x30\x08\xA0\x03\x02\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { :EXPLICIT }
          its(:a) { should == 1 }
          its(:b) { should == true }
          its(:to_der) { should == der }
        end

        context "reject wrong encoding (non-constructed)" do
          let(:der) { "\x30\x08\x80\x03\x02\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { :EXPLICIT }
          it { expect { subject.a }.to raise_error asn1error }
        end

        context "reject wrong encoding" do
          let(:der) { "\x30\x06\x80\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { :EXPLICIT }
          it { expect { subject.a }.to raise_error asn1error }
        end
      end

      context ":CONTEXT_SPECIFIC" do
        it_behaves_like "a non-constructed encoding", :IMPLICIT, "\x80"
      end

      context ":APPLICATION" do
        it_behaves_like "a non-constructed encoding", :APPLICATION, "\x40"
      end

      context ":PRIVATE" do
        it_behaves_like "a non-constructed encoding", :PRIVATE, "\xC0"
      end
    end

    context "optional first field" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a, optional: true
          asn1_boolean :b
          asn1_octet_string :c
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent" do
        let(:der) { "\x30\x06\x01\x01\xFF\x04\x01a" }
        its(:a) { should be_nil }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "optional field between others" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b, optional: true
          asn1_octet_string :c
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should be_nil }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "optional field at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b
          asn1_octet_string :c, optional: true
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should be_nil }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "multiple optional fields at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b
          asn1_octet_string :c, optional: true
          asn1_t61_string :d, optional: true
          asn1_ia5_string :e, optional: true
        end
      end
      
      context "all present" do
        let(:der) { "\x30\x0F\x02\x01\x01\x01\x01\xFF\x04\x01a\x14\x01b\x16\x01c" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "b" }
        its(:e) { should == "c" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "first absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x14\x01b\x16\x01c" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should be_nil }
        its(:d) { should == "b" }
        its(:e) { should == "c" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent between others" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01a\x16\x01c" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should be_nil }
        its(:e) { should == "c" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "last absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01a\x14\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "b"}
        its(:e) { should be_nil }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "all absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should be_nil }
        its(:d) { should be_nil }
        its(:e) { should be_nil }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "single first default value field" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a, default: 42
          asn1_boolean :b
        end
      end
      
      context "present" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent" do
        let(:der) { "\x30\x03\x01\x01\xFF" }
        its(:a) { should == 42 }
        its(:b) { should == true }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "default value field between others" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b, default: false
          asn1_octet_string :c
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == false }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "default value field at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b 
          asn1_octet_string :c, default: "b"
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "multiple default value fields at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b
          asn1_octet_string :c, default: "a"
          asn1_t61_string :d, default: "a"
          asn1_ia5_string :e, default: "a"
        end
      end
      
      context "all present" do
        let(:der) { "\x30\x0F\x02\x01\x01\x01\x01\xFF\x04\x01b\x14\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        its(:d) { should == "b" }
        its(:e) { should == "b" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "first absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x14\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "b" }
        its(:e) { should == "b" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "absent between others" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        its(:d) { should == "a" }
        its(:e) { should == "b" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "last absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01b\x14\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        its(:d) { should == "b"}
        its(:e) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end

      context "all absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "a" }
        its(:e) { should == "a" }
        it { subject.should be_an_instance_of template }
        its(:to_der) { should == der }
      end
    end

    context "default value and optional fields mixed at beginning" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_octet_string :a, optional: true
          asn1_t61_string :b, default: "a"
          asn1_ia5_string :c, default: "a"
          asn1_integer :d
        end
      end

      context "all present" do
        let(:der) { "\x30\x0C\x04\x01b\x14\x01b\x16\x01b\x02\x01\x01" }
        its(:a) { should == "b" }
        its(:b) { should == "b" }
        its(:c) { should == "b" }
        its(:d) { should == 1 }
        its(:to_der) { should == der }
      end

      context "all absent" do
        let(:der) { "\x30\x03\x02\x01\x01" }
        its(:a) { should be_nil }
        its(:b) { should == "a" }
        its(:c) { should == "a" }
        its(:d) { should == 1 }
        its(:to_der) { should == der }
      end

      context "rejects otherwise correct encoding if stream is not consumed" do
        let(:der) { "\x30\x06\x02\x01\x01\x04\x01\x01" } # :d is matched, all others optional or default
        it { expect { subject.a }.to raise_error asn1error }
      end

      context "rejects when wrong encoding is given for an optional field" do
        let(:der) { "\x30\x0C\x01\x01\x00\x14\x01b\x16\x01b\x02\x01\x01" }
        it { expect { subject.a }.to raise_error asn1error }
      end

      context "rejects when wrong encoding is given for a default field" do
        let(:der) { "\x30\x0C\x04\x01\x01\x04\x01b\x16\x01b\x02\x01\x01" }
        it { expect { subject.a }.to raise_error asn1error }
      end

      context "rejects when wrong encoding is given for a default field and the
               optional field is omitted" do
        let(:der) { "\x30\x09\x01\x01\xFF\x16\x01b\x02\x01\x01" }
        it { expect { subject.a }.to raise_error asn1error }
      end
    end

    context "default value and optional fields mixed at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_octet_string :b, optional: true
          asn1_t61_string :c, default: "a"
          asn1_ia5_string :d, default: "a"
        end
      end

      context "all present" do
        let(:der) { "\x30\x0C\x02\x01\x01\x04\x01b\x14\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == "b" }
        its(:c) { should == "b" }
        its(:d) { should == "b" }
        its(:to_der) { should == der }
      end

      context "all absent" do
        let(:der) { "\x30\x03\x02\x01\x01" }
        its(:a) { should == 1 }
        its(:b) { should be_nil }
        its(:c) { should == "a" }
        its(:d) { should == "a" }
        its(:to_der) { should == der }
      end
    end

    context "inner template" do
      let(:template2) do
        Class.new do
          include SEQ
          asn1_boolean :a
        end
      end

      context "at beginning" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t
            asn1_integer :b
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
          its(:to_der) { should == der }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x30\x06\x01\x01\xFF\x02\x01\x01" }
          it { expect { subject.a }.to raise_error asn1error }
        end
      end

      context "at end" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_template :b, t
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x08\x02\x01\x01\x30\x03\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of template2 }
          it { subject.b.a.should == true }
          its(:to_der) { should == der }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x31\x08\x02\x01\x01\x30\x03\x01\x01\xFF" }
          it { expect { subject.a }.to raise_error asn1error }
        end
      end

      context "with implicit tagging" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t, tag: 0, tagging: :IMPLICIT
            asn1_integer :b
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x08\xA0\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
          its(:to_der) { should == der }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          it { expect { subject.a }.to raise_error asn1error }
        end
      end

      context "with explicit tagging" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t, tag: 0, tagging: :EXPLICIT
            asn1_integer :b
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x0A\xA0\x05\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
          its(:to_der) { should == der }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          it { expect { subject.a }.to raise_error asn1error }
        end
      end

      context "optional" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t, optional: true
            asn1_integer :b
          end
        end

        context "present" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
          its(:to_der) { should == der }
        end

        context "absent" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          its(:a) { should be_nil }
          its(:b) { should == 1 }
          its(:to_der) { should == der }
        end
      end

      context "with default value at beginning" do
        let(:template) do
          t = template2
          obj = t.new
          obj.a = false
          Class.new do
            include SEQ
            asn1_template :a, t, default: obj
            asn1_integer :b
          end
        end

        context "present" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
          its(:to_der) { should == der }
        end

        context "absent" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == false }
          its(:b) { should == 1 }
          its(:to_der) { should == der }
        end
      end

      context "with default value at end" do
        let(:template) do
          t = template2
          obj = t.new
          obj.a = false
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_template :b, t, default: obj
          end
        end

        context "present" do
          let(:der) { "\x30\x08\x02\x01\x01\x30\x03\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of template2 }
          it { subject.b.a.should == true }
          its(:to_der) { should == der }
        end

        context "absent" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of template2 }
          it { subject.b.a.should == false }
          its(:to_der) { should == der }
        end
      end
    end

    context "SEQUENCE OF" do
      context "standard" do
        let(:template) do
          t = type
          Class.new do
            include SEQ
            asn1_sequence_of :a, t
          end
        end

        context "multiple Templates" do
          let(:template2) do
            Class.new do
              include SEQ
              asn1_integer :a
            end
          end
          let(:type) { template2 }
          let(:der) { "\x30\x0C\x30\x0A\x30\x03\x02\x01\x01\x30\x03\x02\x01\x01" }
          its(:a) { should be_an_instance_of Array }
          it { subject.a.size.should == 2 }
          it { subject.a.all? { |asn1| asn1.instance_of?(type) && asn1.a == 1 }.should == true }
          its(:to_der) { should == der }
        end

        context "multiple Primitives" do
          let(:type) { Krypt::ASN1::Integer }
          let(:der) { "\x30\x08\x30\x06\x02\x01\x01\x02\x01\x01" }
          its(:a) { should be_an_instance_of Array }
          it { subject.a.size.should == 2 }
          it { subject.a.all? { |asn1| asn1.instance_of?(type) && asn1.value == 1 }.should == true }
          its(:to_der) { should == der }
        end
      end
    end

    context "SET OF" do
      context "standard" do
        let(:template) do
          t = type
          Class.new do
            include SEQ
            asn1_set_of :a, t
          end
        end

        context "multiple Templates" do
          let(:template2) do
            Class.new do
              include SEQ
              asn1_integer :a
            end
          end
          let(:type) { template2 }
          let(:der) { "\x30\x0C\x31\x0A\x30\x03\x02\x01\x01\x30\x03\x02\x01\x01" }
          its(:a) { should be_an_instance_of Array }
          it { subject.a.size.should == 2 }
          it { subject.a.all? { |asn1| asn1.instance_of?(type) && asn1.a == 1 }.should == true }
          its(:to_der) { should == der }
        end

        context "multiple Primitives" do
          let(:type) { Krypt::ASN1::Integer }
          let(:der) { "\x30\x08\x31\x06\x02\x01\x01\x02\x01\x01" }
          its(:a) { should be_an_instance_of Array }
          it { subject.a.size.should == 2 }
          it { subject.a.all? { |asn1| asn1.instance_of?(type) && asn1.value == 1 }.should == true }
          its(:to_der) { should == der }
        end
      end
    end

    context "ANY values" do
      context "at beginning" do
        let(:template) do
          Class.new do
            include SEQ
            asn1_any :a
            asn1_boolean :b
          end
        end

        context "as primitive value" do
          let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
          its(:a) { should be_an_instance_of Krypt::ASN1::Integer }
          it { subject.a.value.should == 1 }
          its(:b) { should == true }
          its(:to_der) { should == der }
        end

        context "as sequence" do
          let(:der) { "\x30\x0B\x30\x06\x02\x01\x01\x02\x01\x01\x01\x01\xFF" }
          its(:a) { should be_an_instance_of Krypt::ASN1::Sequence }
          it { subject.a.value.should be_an_instance_of Array }
          it { subject.a.value.size.should == 2 }
          it { subject.a.value.all? { |v| v.instance_of?(Krypt::ASN1::Integer) && v.value == 1 }.should == true }
          its(:b) { should == true }
          its(:to_der) { should == der }
        end
      end

      context "at end" do
        let(:template) do
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_any :b
          end
        end

        context "as primitive value" do
          let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of Krypt::ASN1::Boolean }
          it { subject.b.value.should == true }
          its(:to_der) { should == der }
        end

        context "as sequence" do
          let(:der) { "\x30\x0B\x02\x01\x02\x30\x06\x02\x01\x01\x02\x01\x01" }
          its(:a) { should == 2 }
          its(:b) { should be_an_instance_of Krypt::ASN1::Sequence }
          it { subject.b.value.should be_an_instance_of Array }
          it { subject.b.value.size.should == 2 }
          it { subject.b.value.all? { |v| v.instance_of?(Krypt::ASN1::Integer) && v.value == 1 }.should == true }
          its(:to_der) { should == der }
        end
      end

      context "optionally and tagged between mandatory" do
        let(:template) do
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_any :b, tag: 0, tagging: :IMPLICIT, optional: true
            asn1_boolean :c
          end
        end

        context "present" do
          let(:der) { "\x30\x09\x02\x01\x01\x80\x01a\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of Krypt::ASN1::ASN1Data }
          it { subject.b.value.should == "a" }
          it { subject.b.tag.should == 0 }
          it { subject.b.tag_class.should == :CONTEXT_SPECIFIC }
          its(:c) { should == true }
          its(:to_der) { should == der }
        end

        context "absent" do
          let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_nil }
          its(:c) { should == true }
          its(:to_der) { should == der }
        end
      end

      context "tagged with default" do
        let(:null) { Krypt::ASN1::Null.new }
        context
        let(:template) do
          n = null
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_any :b, tag: 0, tagging: :IMPLICIT, default: n
            asn1_boolean :c
          end
        end

        context "present" do
          let(:der) { "\x30\x09\x02\x01\x01\x80\x01a\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of Krypt::ASN1::ASN1Data }
          it { subject.b.value.should == "a" }
          it { subject.b.tag.should == 0 }
          it { subject.b.tag_class.should == :CONTEXT_SPECIFIC }
          its(:c) { should == true }
          its(:to_der) { should == der }
        end

        context "absent" do
          let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should == null }
          its(:c) { should == true }
          its(:to_der) { should == der }
        end
      end
    end

    context "inner CHOICEs" do
      context "rejects tagging other than :EXPLICIT" do
        let(:choice) do
          Class.new do
            include Krypt::ASN1::Template::Choice
            asn1_integer
          end
        end
        let(:template) do
          c = choice
          tc = tagging
          Class.new do
            include SEQ
            asn1_template :a, c, tag: 0, tagging: tc
          end
        end

        context ":IMPLICIT" do
          let(:tagging) { :IMPLICIT }
          let(:der) { "\x30\x03\x80\x01\x01" }
          it { expect { subject.a.value }.to raise_error asn1error }
        end

        context ":CONTEXT_SPECIFIC" do
          let(:tagging) { :CONTEXT_SPECIFIC }
          let(:der) { "\x30\x03\x80\x01\x01" }
          it { expect { subject.a.value }.to raise_error asn1error }
        end

        context ":APPLICATION" do
          let(:tagging) { :APPLICATION }
          let(:der) { "\x30\x03\x40\x01\x01" }
          it { expect { subject.a.value }.to raise_error asn1error }
        end

        context ":PRIVATE" do
          let(:tagging) { :PRIVATE }
          let(:der) { "\x30\x03\xC0\x01\x01" }
          it { expect { subject.a.value }.to raise_error asn1error }
        end

        #Can be argued. For now, let's not endorse redundancy
        context ":UNIVERSAL" do
          let(:tagging) { :UNIVERSAL }
          let(:der) { "\x30\x03\x02\x01\x01" }
          it { expect { subject.a.value }.to raise_error asn1error }
        end

        context ":EXPLICIT" do
          let(:tagging) { :EXPLICIT }
          let(:der) { "\x30\x05\xA0\x03\x02\x01\x01" }
          it { expect { subject.a.value }.to_not raise_error }
        end
      end

      context "at beginning, primitive choices only" do
        let(:choice) do
          Class.new do
            include Krypt::ASN1::Template::Choice
            asn1_integer
            asn1_boolean
          end
        end
        let(:template) do
          c = choice
          Class.new do
            include SEQ
            asn1_template :a, c
            asn1_octet_string :b
          end
        end

        context "match first" do
          let(:der) { "\x30\x06\x02\x01\x01\x04\x01a" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.type.should == Krypt::ASN1::INTEGER }
          it { subject.a.tag.should == Krypt::ASN1::INTEGER }
          it { subject.a.value.should == 1 }
          its(:b) { should == "a" }
          its(:to_der) { should == der }
        end

        context "match second" do
          let(:der) { "\x30\x06\x01\x01\xFF\x04\x01a" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.type.should == Krypt::ASN1::BOOLEAN }
          it { subject.a.tag.should == Krypt::ASN1::BOOLEAN }
          it { subject.a.value.should == true }
          its(:b) { should == "a" }
          its(:to_der) { should == der }
        end
      end

      context "with inner tags" do
        let(:choice) do
          Class.new do
            include Krypt::ASN1::Template::Choice
            asn1_integer tag: 0, tagging: :IMPLICIT
            asn1_boolean tag: 1, tagging: :EXPLICIT
          end
        end
        let(:template) do
          c = choice
          Class.new do
            include SEQ
            asn1_template :a, c
            asn1_octet_string :b
          end
        end

        context "match first" do
          let(:der) { "\x30\x06\x80\x01\x01\x04\x01a" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.type.should == Krypt::ASN1::INTEGER }
          it { subject.a.tag.should == 0 }
          it { subject.a.value.should == 1 }
          its(:b) { should == "a" }
          its(:to_der) { should == der }
        end

        context "match second" do
          let(:der) { "\x30\x08\xA1\x03\x01\x01\xFF\x04\x01a" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.type.should == Krypt::ASN1::BOOLEAN }
          it { subject.a.tag.should == 1 }
          it { subject.a.value.should == true }
          its(:b) { should == "a" }
          its(:to_der) { should == der }
        end
      end

      context "primitive choices only, explicitly tagged and default value" do
        let(:choice) do
          Class.new do
            include Krypt::ASN1::Template::Choice
            asn1_integer
            asn1_boolean
          end
        end
        let(:default_value) do
          choice.new do |o|
            o.type = Krypt::ASN1::INTEGER
            o.value = 42
          end
        end
        let(:template) do
          c = choice
          v = default_value
          Class.new do
            include SEQ
            asn1_template :a, c, tag: 0, tagging: :EXPLICIT, default: v
            asn1_octet_string :b
          end
        end

        context "present, match first" do
          let(:der) { "\x30\x08\xA0\x03\x02\x01\x01\x04\x01a" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.type.should == Krypt::ASN1::INTEGER }
          it { subject.a.tag.should == 2 } # it's the tag within the choice, the outer tag doesn't matter
          it { subject.a.value.should == 1 }
          its(:b) { should == "a" }
          its(:to_der) { should == der }
        end

        context "present, match second" do
          let(:der) { "\x30\x08\xA0\x03\x01\x01\xFF\x04\x01a" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.type.should == Krypt::ASN1::BOOLEAN }
          it { subject.a.tag.should == 1 } # it's the tag within the choice, the outer tag doesn't matter
          it { subject.a.value.should == true }
          its(:b) { should == "a" }
          its(:to_der) { should == der }
        end

        context "absent" do
          let(:der) { "\x30\x03\x04\x01a" }
          its(:a) { should == default_value }
          its(:b) { should == "a" }
          its(:to_der) { should == der }
        end
      end

      context "with inner tagged templates, while outer CHOICE is explicitly tagged" do
        let(:template2) do
          Class.new do
            include Krypt::ASN1::Template::Sequence
            asn1_integer :a
          end
        end
        let(:template3) do
          Class.new do
            include Krypt::ASN1::Template::Sequence
            asn1_boolean :a
          end
        end
        let(:choice) do
          t2 = template2
          t3 = template3
          Class.new do
            include Krypt::ASN1::Template::Choice
            asn1_template t2, tag: 0, tagging: :IMPLICIT
            asn1_template t3, tag: 1, tagging: :EXPLICIT
          end
        end
        let(:template) do
          c = choice
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_template :b, c, tag: 2, tagging: :EXPLICIT
          end
        end

        context "match first" do
          let(:der) { "\x30\x0A\x02\x01\x01\xA2\x05\xA0\x03\x02\x01\x01" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of choice }
          it { subject.b.type.should == template2 }
          it { subject.b.tag.should == 0 } # it's the tag within the choice, the outer tag doesn't matter
          it { subject.b.value.should be_an_instance_of template2 }
          it { subject.b.value.a.should == 1 }
          its(:to_der) { should == der }
        end

        context "match second" do
          let(:der) { "\x30\x0C\x02\x01\x01\xA2\x07\xA1\x05\x30\x03\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of choice }
          it { subject.b.type.should == template3 }
          it { subject.b.tag.should == 1 } # it's the tag within the choice, the outer tag doesn't matter
          it { subject.b.value.should be_an_instance_of template3 }
          it { subject.b.value.a.should == true }
          its(:to_der) { should == der }
        end
      end

      context "integer and SEQUENCE OF template" do
        let(:template2) do
          Class.new do
            include Krypt::ASN1::Template::Sequence
            asn1_integer :a
          end
        end
        let(:seqof) do
          t2 = template2
          Class.new do
            include Krypt::ASN1::Template::SequenceOf
            asn1_type t2
          end
        end
        let(:choice) do
          sof = seqof
          Class.new do
            include Krypt::ASN1::Template::Choice
            asn1_integer
            asn1_template sof
          end
        end
        let(:template) do
          c = choice
          Class.new do
            include SEQ
            asn1_template :a, c
          end
        end

        context "match integer" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.tag.should == Krypt::ASN1::INTEGER }
          it { subject.a.type.should == Krypt::ASN1::INTEGER }
          it { subject.a.value.should == 1 }
        end

        context "match SEQUENCE OF template" do
          let(:der) { "\x30\x0C\x30\x0A\x30\x03\x02\x01\x01\x30\x03\x02\x01\x01" }
          its(:a) { should be_an_instance_of choice }
          it { subject.a.tag.should == Krypt::ASN1::SEQUENCE }
          it { subject.a.type.should == seqof }
          it { subject.a.value.should be_an_instance_of seqof }
          it { subject.a.value.value.should be_an_instance_of Array }
          it { subject.a.value.value.size.should == 2 }
          it { subject.a.value.value.all? { |v| v.instance_of?(template2) && v.a == 1 }.should == true }
        end
      end
    end
  end
end

