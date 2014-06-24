# encoding: US-ASCII

require 'rspec'
require 'krypt'
require 'stringio'
require 'base64'
require_relative '../resources'

describe Krypt::PEM do
  let(:mod) { Krypt::PEM }
  let(:pemerror) { Krypt::PEM::PEMError }
  let(:intb64) { ::Base64.encode64("\x02\x01\x01") }

  def create_pem_b64(b64, name)
    "-----BEGIN #{name}-----\n#{b64}-----END #{name}-----\n"
  end

  describe "PEM.decode" do
    subject { mod.decode(value) }

    context "returns an Array" do
      let(:value) { Resources.certificate_pem }
      it { should be_an_instance_of(Array) }
    end

    context"decodes Strings" do
      context "decodes a single PEM value" do
        let(:value) { Resources.certificate_pem }
        its(:size) { should == 1 }
        it { subject[0].should == Resources.certificate }
      end

      context "decodes multiple PEM values" do
        let(:value) { Resources.certificate_pem * 3 }
        its(:size) { should == 3 }
        it { subject.all? { |der| der == Resources.certificate }.should be_true }
      end

      context "decodes multiple mixed PEM values" do
        let(:value) { Resources.certificate_pem + create_pem_b64(intb64, "INTEGER") }
        its(:size) { should == 2 }
        it do
          subject[0].should == Resources.certificate
          subject[1].should == "\x02\x01\x01"
        end
      end

      context "decodes long PEM values" do
        let(:der) { "\x04\x82\x4E\x20" + "\x01" * 20_000 }
        let(:value) { create_pem_b64("#{::Base64.encode64(der)}", "OCTET STRING") }
        its(:size) { should == 1 }
        it { subject[0].should == der }
      end
    end

    context "decodes StringIO" do
      context "decodes a single PEM value" do
        let(:value) { StringIO.new(Resources.certificate_pem) }
        its(:size) { should == 1 }
        it { subject[0].should == Resources.certificate }
      end

      context "decodes multiple PEM values" do
        let(:value) { StringIO.new(Resources.certificate_pem * 3) }
        its(:size) { should == 3 }
        it { subject.all? { |der| der == Resources.certificate }.should be_true }
      end
    end

    context "decodes Files" do
      subject do
        begin
          mod.decode(io)
        ensure
          io.close
        end
      end

      context "decodes a File containing a single PEM value" do
        let(:io) { Resources.certificate_pem_io }
        its(:size) { should == 1 }
        it { subject[0].should == Resources.certificate }
      end

      context "decodes a File containing multiple PEM values" do
        let(:io) { Resources.multi_certificate_pem_io }
        its(:size) { should == 3 }
        it { subject.all? { |der| der == Resources.certificate }.should be_true }
      end
    end
    
    context "decodes arbitrary objects that respond to to_pem" do
      let(:value) do
        o = Object.new
        def o.to_pem
          Resources.certificate_pem
        end
        o
      end
      its(:size) { should == 1 }
      it { subject[0].should == Resources.certificate }
    end

    context "does not require terminating line break" do
      let(:value) { "-----BEGIN ABC-----\n#{intb64}-----END ABC-----" }
      its(:size) { should == 1 }
      it { subject[0].should == "\x02\x01\x01" }
    end

    context "ignores empty lines" do
      context "LF" do
        let(:value) { "\n" + create_pem_b64("\n#{intb64}\n", "INTEGER") + "\n" }
        its(:size) { should == 1 }
        it { subject[0].should == "\x02\x01\x01" }
      end

      context "CRLF" do
        let(:value) { "\r\n" + create_pem_b64("\r\n#{intb64}\r\n", "INTEGER") + "\r\n" }
        its(:size) { should == 1 }
        it { subject[0].should == "\x02\x01\x01" }
      end
    end

    context "normalizes CRLF and LF" do
      context "LF only" do
        let(:value) { "-----BEGIN A-----\n#{intb64}-----END A-----\n" }
        it { subject[0].should == "\x02\x01\x01" }
      end

      context "CRLF only" do
        let(:value) { "-----BEGIN A-----\r\n#{::Base64.encode64("\x02\x01\x01")}\r\n-----END A-----\r\n" }
        it { subject[0].should == "\x02\x01\x01" }
      end

      context "mixed: CRLF header, LF footer" do
        let(:value) { "-----BEGIN A-----\r\n#{intb64}-----END A-----\n" }
        it { subject[0].should == "\x02\x01\x01" }
      end

      context "mixed: LF header, CRLF footer" do
        let(:value) { "-----BEGIN A-----\n#{intb64}-----END A-----\r\n" }
        it { subject[0].should == "\x02\x01\x01" }
      end
    end

    context "allows arbitrary content between PEM blocks" do
      context "String with LF as last character" do
        let(:value) { "Next up a certificate.\n#{Resources.certificate_pem}After the certificate\n" }
        its(:size) { should == 1 }
        it { subject[0].should == Resources.certificate }
      end

      context "String not ending in LF as last character" do
        let(:value) { "Next up a certificate.\n#{Resources.certificate_pem}After the certificate" }
        its(:size) { should == 1 }
        it { subject[0].should == Resources.certificate }
      end

      context "File containing a 'CA certificate bundle'" do
        let(:value) { Resources.ca_certificate_pem_io }
        its(:size) { should == 136 }
      end
    end

    context "rejects values with non-matching names" do
      let(:value) { "-----BEGIN A-----\n#{intb64}-----END B-----" }
      it { expect { subject }.to raise_error pemerror }
    end

    context "allows no redundant whitespace" do
      context"leading in header" do
        let(:value) { " -----BEGIN A-----\n#{intb64}-----END A-----" }
        it { subject.should be_empty }
      end

      context"leading in footer" do
        let(:value) { "-----BEGIN A-----\n#{intb64} -----END A-----" }
        it { expect { subject }.to raise_error pemerror }
      end
 
      context"trailing in header" do
        let(:value) { "-----BEGIN A----- \n#{intb64}-----END A-----" }
        it { subject.should be_empty }
      end

      context"trailing in footer" do
        let(:value) { "-----BEGIN A-----\n#{intb64}-----END A----- " }
        it { expect { subject }.to raise_error pemerror }
      end
    end

    context "does not expect line breaks for Base64 content" do
      context "in small data" do
        let(:der) { "\x04\x82\x03\xE8" + "\x01" * 80 }
        let(:value) { "-----BEGIN ABC-----\n#{::Base64.strict_encode64(der)}\n-----END ABC-----" }
        it { subject[0].should == der }
      end

      context "in large data" do
        let(:der) { "\x04\x82\x4E\x20" + "\x01" * 20_000 }
        let(:value) { "-----BEGIN ABC-----\n#{::Base64.strict_encode64(der)}\n-----END ABC-----" }
        it { subject[0].should == der }
      end
    end

    context "takes a block" do
      context "whose first argument is the current value" do
        let(:value) { Resources.certificate_pem * 3 }
        it do
          ary = []
          cmp = mod.decode(value) { |asn1| ary << asn1 }
          ary.should == cmp
        end
      end

      context "whose second argument is the name of the current value" do
        let(:value) { Resources.certificate_pem * 3 }
        it do
          ary = []
          mod.decode(value) { |asn1, name| ary << name }
          ary.should == ["CERTIFICATE", "CERTIFICATE", "CERTIFICATE"]
        end
      end

      context "whose third argument is the current index, starting at 0" do
        let(:value) { Resources.certificate_pem * 3 }
        it do
          ary = []
          mod.decode(value) { |asn1, name, i| ary << i }
          ary.should == [0,1,2]
        end
      end
    end
  end
end
