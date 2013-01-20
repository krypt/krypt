require 'rspec'
require 'krypt'

describe Krypt::Hex do 

  let(:mod) { Krypt::Hex }

  describe "encode" do
    context "single parameter data" do
      context "RFC 4648 test vectors" do
        specify "empty string" do
          mod.encode("").should == ""
        end

        specify "f" do
          mod.encode("f").should == "66"
        end

        specify "fo" do
          mod.encode("fo").should == "666f"
        end

        specify "foo" do
          mod.encode("foo").should == "666f6f"
        end

        specify "foob" do
          mod.encode("foob").should == "666f6f62"
        end

        specify "fooba" do
          mod.encode("fooba").should == "666f6f6261"
        end

        specify "foobar" do
          mod.encode("foobar").should == "666f6f626172"
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
        mod.decode("66").should == "f"
      end

      specify "fo" do
        mod.decode("666f").should == "fo"
      end

      specify "foo" do
        mod.decode("666f6f").should == "foo"
      end

      specify "foob" do
        mod.decode("666f6f62").should == "foob"
      end

      specify "fooba" do
        mod.decode("666f6f6261").should == "fooba"
      end

      specify "foobar" do
        mod.decode("666f6f626172").should == "foobar"
      end
    end

    it "should return a string with binary encoding" do
      mod.decode("666f6f626172").encoding.should == Encoding::BINARY
    end

    it "should return a string with US-ASCII encoding even if
        the underlying encoding is not" do
      data = "666f"
      data.force_encoding(Encoding::UTF_8)
      mod.decode(data).encoding.should == Encoding::BINARY
    end

    it "ignores case for a-f" do
      str = "666f6f626172"
      dec = "foobar"
      mod.decode(str).should == dec
      mod.decode(str.upcase).should == dec 
    end
  end
end
