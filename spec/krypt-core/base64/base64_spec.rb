require 'rspec'
require 'krypt'

describe Krypt::Base64 do 

  let(:mod) { Krypt::Base64 }

  describe "encode" do
    context "single parameter data" do
      context "RFC 4648 test vectors" do
        specify "empty string" do
          mod.encode("").should == ""
        end

        specify "f" do
          mod.encode("f").should == "Zg=="
        end

        specify "fo" do
          mod.encode("fo").should == "Zm8="
        end

        specify "foo" do
          mod.encode("foo").should == "Zm9v"
        end

        specify "foob" do
          mod.encode("foob").should == "Zm9vYg=="
        end

        specify "fooba" do
          mod.encode("fooba").should == "Zm9vYmE="
        end

        specify "foobar" do
          mod.encode("foobar").should == "Zm9vYmFy"
        end
      end
    end

    it "should return a string with US-ASCII encoding" do
      mod.encode("test").encoding.should == Encoding::US_ASCII
    end

    it "should return a string with US-ASCII encoding even if
        the underlying encoding is not" do
      auml = [%w{ C3 A4 }.join('')].pack('H*')
      auml.force_encoding(Encoding::UTF_8)
      mod.encode(auml).encoding.should == Encoding::US_ASCII
    end
  end

  describe "decode" do
    context "RFC 4648 test vectors" do
      specify "empty string" do
        mod.decode("").should == ""
      end

      specify "f" do
        mod.decode("Zg==").should == "f"
      end

      specify "fo" do
        mod.decode("Zm8=").should == "fo"
      end

      specify "foo" do
        mod.decode("Zm9v").should == "foo"
      end

      specify "foob" do
        mod.decode("Zm9vYg==").should == "foob"
      end

      specify "fooba" do
        mod.decode("Zm9vYmE=").should == "fooba"
      end

      specify "foobar" do
        mod.decode("Zm9vYmFy").should == "foobar"
      end
    end

    it "should return a string with binary encoding" do
      mod.decode("Zm9vYmE=").encoding.should == Encoding::BINARY
    end

    it "should return a string with binary encoding even if
        the underlying encoding is not" do
      auml = [%w{ C3 A4 }.join('')].pack('H*')
      auml.force_encoding(Encoding::UTF_8)
      mod.decode(auml).encoding.should == Encoding::BINARY
    end
  end

end

