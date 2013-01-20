require 'rspec'
require 'krypt'
require 'stringio'

describe Krypt::Base64::Decoder do 

  let(:klass) { Krypt::Base64::Decoder }

  def write_string(s)
    io = StringIO.new
    b64 = klass.new(io)
    b64 << s
    b64.close
    io.string
  end

  def read_string(s)
    io = StringIO.new(s)
    b64 = klass.new(io)
    begin
      b64.read
    ensure
      b64.close
    end
  end

  describe "new" do
    it "mandates a single parameter, the underlying IO" do
      klass.new(StringIO.new).should be_an_instance_of klass
    end

    context "takes a block after whose execution the IO is closed" do
      specify "successful execution of the block" do
        io = StringIO.new
        klass.new(io) do |b64|
          b64 << "Zg=="
        end
        io.closed?.should == true
      end

      specify "failed execution of the block" do
        io = StringIO.new
        begin
          klass.new(io) do |b64|
            raise RuntimeError.new 
          end
        rescue RuntimeError
          io.closed?.should == true
        end
      end
    end
  end

  shared_examples_for "RFC 4648 Base64 decode" do |meth|
    context "RFC 4648 test vectors" do
      specify "empty string" do
        send(meth, "").should == ""
      end

      specify "f" do
        send(meth, "Zg==").should == "f"
      end

      specify "fo" do
        send(meth, "Zm8=").should == "fo"
      end

      specify "foo" do
        send(meth, "Zm9v").should == "foo"
      end

      specify "foob" do
        send(meth, "Zm9vYg==").should == "foob"
      end

      specify "fooba" do
        send(meth, "Zm9vYmE=").should == "fooba"
      end

      specify "foobar" do
        send(meth, "Zm9vYmFy").should == "foobar"
      end
    end
  end

  describe "#read" do
    it_behaves_like "RFC 4648 Base64 decode", :read_string
  end

  describe "#write" do
    it_behaves_like "RFC 4648 Base64 decode", :write_string
  end

end
