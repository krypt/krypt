require 'rspec'
require 'krypt'
require 'stringio'

describe Krypt::Hex::Encoder do 

  let(:klass) { Krypt::Hex::Encoder }

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
          hex << "test"
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

  shared_examples_for "RFC 4648 hex encode" do |meth|
    context "RFC 4648 test vectors" do
      specify "empty string" do
        send(meth, "").should == ""
      end

      specify "f" do
        send(meth, "f").should == "66"
      end

      specify "fo" do
        send(meth, "fo").should == "666f"
      end

      specify "foo" do
        send(meth, "foo").should == "666f6f"
      end

      specify "foob" do
        send(meth, "foob").should == "666f6f62"
      end

      specify "fooba" do
        send(meth, "fooba").should == "666f6f6261"
      end

      specify "foobar" do
        send(meth, "foobar").should == "666f6f626172"
      end
    end
  end

  describe "#read" do
    it_behaves_like "RFC 4648 hex encode", :read_string
  end

  describe "#write" do
    it_behaves_like "RFC 4648 hex encode", :write_string
  end

end
