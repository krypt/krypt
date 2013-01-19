require 'rspec'
require 'krypt'

describe "Krypt::PBKDF2" do 

  let(:pb) { Krypt::PBKDF2 }

  describe "#generate" do
    it "returns a String with binary encoding" do
      pbkdf = pb.new(Krypt::Digest::SHA1.new)
      pbkdf.generate("pwd", "salt", 1, 20).encoding.should == Encoding::BINARY
    end
  end

  describe "#generate_hex" do
    it "returns a String with US-ASCII encoding" do
      pbkdf = pb.new(Krypt::Digest::SHA1.new)
      pbkdf.generate_hex("pwd", "salt", 1, 20).encoding.should == Encoding::US_ASCII
    end
  end

  context "conforms to RFC6070 test vectors" do
    let(:instance) { pb.new(Krypt::Digest::SHA1.new) }
    let(:binary) { instance.generate(pwd, salt, iter, len) }
    let(:hex) { instance.generate_hex(pwd, salt, iter, len) }

    context "#1" do
      let(:pwd) { "password" }
      let(:salt) { "salt" }
      let(:iter) { 1 }
      let(:len) { 20 }
      let(:expected) { "0c60c80f961f0e71f3a9b524af6012062fe037a6" }
      it { binary.should == Krypt::Hex.decode(expected) }
      it { hex.should == expected }
    end

    context "#2" do
      let(:pwd) { "password" }
      let(:salt) { "salt" }
      let(:iter) { 2 }
      let(:len) { 20 }
      let(:expected) { "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957" }
      it { binary.should == Krypt::Hex.decode(expected) }
      it { hex.should == expected }
    end

    context "#3" do
      let(:pwd) { "password" }
      let(:salt) { "salt" }
      let(:iter) { 4096 }
      let(:len) { 20 }
      let(:expected) { "4b007901b765489abead49d926f721d065a429c1" }
      it { binary.should == Krypt::Hex.decode(expected) }
      it { hex.should == expected }
    end

    # omit #4 because it takes too long
    context "#5" do
      let(:pwd) { "passwordPASSWORDpassword" }
      let(:salt) { "saltSALTsaltSALTsaltSALTsaltSALTsalt" }
      let(:iter) { 4096 }
      let(:len) { 25 }
      let(:expected) { "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038" }
      it { binary.should == Krypt::Hex.decode(expected) }
      it { hex.should == expected }
    end

    context "#6" do
      let(:pwd) { "pass\0word" }
      let(:salt) { "sa\0lt" }
      let(:iter) { 4096 }
      let(:len) { 16 }
      let(:expected) { "56fa6aa75548099dcc37d7f03425e0c3" }
      it { binary.should == Krypt::Hex.decode(expected) }
      it { hex.should == expected }
    end
  end

end
