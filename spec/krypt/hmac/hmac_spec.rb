require 'rspec'
require 'krypt'

describe "Krypt::HMAC" do 

  let(:hmac) { Krypt::HMAC }

  describe "#digest" do
    it "returns a String with binary encoding" do
      mac = hmac.new(Krypt::Digest::SHA1.new, "key")
      mac << "test"
      mac.digest.encoding.should == Encoding::BINARY
    end
  end

  describe "#hex_digest" do
    it "returns a String with US-ASCII encoding" do
      mac = hmac.new(Krypt::Digest::SHA1.new, "key")
      mac << "test"
      mac.hexdigest.encoding.should == Encoding::US_ASCII
    end
  end

  context "conforms to RFC2202 test vectors" do
    context "MD5" do
      let(:binary) { hmac.digest(Krypt::Digest::MD5.new, key, data) }

      context "test_case 1" do
        let(:key) { Krypt::Hex.decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" }
        let(:data) { "Hi There" }
        let(:expected) { "9294727a3638bb1c13f48ef8158bfc9d" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 2" do
        let(:key) { "Jefe" }
        let(:data) { "what do ya want for nothing?" }
        let(:expected) { "750c783e6ab0b503eaa86e310a5db738" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 3" do
        let(:key) { Krypt::Hex.decode "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        let(:data) { "\xdd" * 50 }
        let(:expected) { "56be34521d144c88dbb8c733f0e8b3f6" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 4" do
        let(:key) { Krypt::Hex.decode "0102030405060708090a0b0c0d0e0f10111213141516171819" }
        let(:data) { "\xcd" * 50 }
        let(:expected) { "697eaf0aca3a3aea3a75164746ffaa79" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 5" do
        let(:key) { Krypt::Hex.decode "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }
        let(:data) { "Test With Truncation" }
        let(:expected) { "56461ef2342edc00f9bab995690efd4c" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 6" do
        let(:key) { "\xaa" * 80 }
        let(:data) { "Test Using Larger Than Block-Size Key - Hash Key First" }
        let(:expected) { "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 7" do
        let(:key) { "\xaa" * 80 }
        let(:data) { "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" }
        let(:expected) { "6f630fad67cda0ee1fb1f562db3aa53e" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end
    end

    context "SHA1" do
      let(:binary) { hmac.digest(Krypt::Digest::SHA1.new, key, data) }

      context "test_case 1" do
        let(:key) { Krypt::Hex.decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" }
        let(:data) { "Hi There" }
        let(:expected) { "b617318655057264e28bc0b6fb378c8ef146be00" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 2" do
        let(:key) { "Jefe" }
        let(:data) { "what do ya want for nothing?" }
        let(:expected) { "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 3" do
        let(:key) { Krypt::Hex.decode "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        let(:data) { "\xdd" * 50 }
        let(:expected) { "125d7342b9ac11cd91a39af48aa17b4f63f175d3" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 4" do
        let(:key) { Krypt::Hex.decode "0102030405060708090a0b0c0d0e0f10111213141516171819" }
        let(:data) { "\xcd" * 50 }
        let(:expected) { "4c9007f4026250c6bc8414f9bf50c86c2d7235da" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 5" do
        let(:key) { Krypt::Hex.decode "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }
        let(:data) { "Test With Truncation" }
        let(:expected) { "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 6" do
        let(:key) { "\xaa" * 80 }
        let(:data) { "Test Using Larger Than Block-Size Key - Hash Key First" }
        let(:expected) { "aa4ae5e15272d00e95705637ce8a3b55ed402112" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end

      context "test_case 7" do
        let(:key) { "\xaa" * 80 }
        let(:data) { "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" }
        let(:expected) { "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" }
        it { binary.should == Krypt::Hex.decode(expected) }
      end
    end
  end

end
