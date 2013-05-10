require 'rspec'
require 'krypt'
require 'stringio'

describe Krypt::Hex::Decoder do 

  let(:klass) { Krypt::Hex::Decoder }

  def write_string(s)
    io = StringIO.new
    hex = klass.new(io)
    hex << s
    hex.close
    io.string
  end

  def read_string(s)
    io = StringIO.new(s)
    hex = klass.new(io)
    begin
      hex.read
    ensure
      hex.close
    end
  end

  describe "new" do
    it "mandates a single parameter, the underlying IO" do
      klass.new(StringIO.new).should be_an_instance_of klass
    end

    context "takes a block after whose execution the IO is closed" do
      specify "successful execution of the block" do
        io = StringIO.new
        klass.new(io) do |hex|
          hex << "42"
        end
        io.closed?.should == true
      end

      specify "failed execution of the block" do
        io = StringIO.new
        begin
          klass.new(io) do
            raise RuntimeError.new 
          end
        rescue RuntimeError
          io.closed?.should == true
        end
      end
    end
  end

  shared_examples_for "RFC 4648 hex decode" do |meth|
    context "RFC 4648 test vectors" do
      specify "empty string" do
        send(meth, "").should == ""
      end

      specify "f" do
        send(meth, "66").should == "f"
      end

      specify "fo" do
        send(meth, "666f").should == "fo"
      end

      specify "foo" do
        send(meth, "666f6f").should == "foo"
      end

      specify "foob" do
        send(meth, "666f6f62").should == "foob"
      end

      specify "fooba" do
        send(meth, "666f6f6261").should == "fooba"
      end

      specify "foobar" do
        send(meth, "666f6f626172").should == "foobar"
      end
    end
  end

  describe "#read" do
    it_behaves_like "RFC 4648 hex decode", :read_string
  end

  describe "#write" do
    it_behaves_like "RFC 4648 hex decode", :write_string
  end

end
