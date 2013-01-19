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

  context "conforms to RFC4231 test vectors" do
    subject { hmac.hexdigest(digest, key, data) }

    context "Test case 1" do
      let(:key) { Krypt::Hex.decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" }
      let(:data) { "Hi There" }

      context "SHA-224" do
        let(:digest) { Krypt::Digest::SHA224.new }
        it { subject.should == "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22" }
      end

      context "SHA-256" do
        let(:digest) { Krypt::Digest::SHA256.new }
        it { subject.should == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" }
      end

      context "SHA-384" do
        let(:digest) { Krypt::Digest::SHA384.new }
        it { subject.should == "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" }
      end

      context "SHA-512" do
        let(:digest) { Krypt::Digest::SHA512.new }
        it { subject.should == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" }
      end
    end

    context "Test case 2" do
      let(:key) { "Jefe" }
      let(:data) { "what do ya want for nothing?" }

      context "SHA-224" do
        let(:digest) { Krypt::Digest::SHA224.new }
        it { subject.should == "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44" }
      end

      context "SHA-256" do
        let(:digest) { Krypt::Digest::SHA256.new }
        it { subject.should == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" }
      end

      context "SHA-384" do
        let(:digest) { Krypt::Digest::SHA384.new }
        it { subject.should == "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649" }
      end

      context "SHA-512" do
        let(:digest) { Krypt::Digest::SHA512.new }
        it { subject.should == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" }
      end
    end

    context "Test case 3" do
      let(:key) { Krypt::Hex.decode "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
      let(:data) { "\xdd" * 50 }

      context "SHA-224" do
        let(:digest) { Krypt::Digest::SHA224.new }
        it { subject.should == "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea" }
      end

      context "SHA-256" do
        let(:digest) { Krypt::Digest::SHA256.new }
        it { subject.should == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" }
      end

      context "SHA-384" do
        let(:digest) { Krypt::Digest::SHA384.new }
        it { subject.should == "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27" }
      end

      context "SHA-512" do
        let(:digest) { Krypt::Digest::SHA512.new }
        it { subject.should == "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb" }
      end
    end

    context "Test case 4" do
      let(:key) { Krypt::Hex.decode "0102030405060708090a0b0c0d0e0f10111213141516171819" }
      let(:data) { "\xcd" * 50 }

      context "SHA-224" do
        let(:digest) { Krypt::Digest::SHA224.new }
        it { subject.should == "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a" }
      end

      context "SHA-256" do
        let(:digest) { Krypt::Digest::SHA256.new }
        it { subject.should == "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" }
      end

      context "SHA-384" do
        let(:digest) { Krypt::Digest::SHA384.new }
        it { subject.should == "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb" }
      end

      context "SHA-512" do
        let(:digest) { Krypt::Digest::SHA512.new }
        it { subject.should == "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd" }
      end
    end

    context "Test case 5" do
      let(:key) { Krypt::Hex.decode "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }
      let(:data) { "Test With Truncation" }

      context "SHA-224" do
        let(:digest) { Krypt::Digest::SHA224.new }
        it { subject.slice(0, 32).should == "0e2aea68a90c8d37c988bcdb9fca6fa8" }
      end

      context "SHA-256" do
        let(:digest) { Krypt::Digest::SHA256.new }
        it { subject.slice(0, 32).should == "a3b6167473100ee06e0c796c2955552b" }
      end

      context "SHA-384" do
        let(:digest) { Krypt::Digest::SHA384.new }
        it { subject.slice(0, 32).should == "3abf34c3503b2a23a46efc619baef897" }
      end

      context "SHA-512" do
        let(:digest) { Krypt::Digest::SHA512.new }
        it { subject.slice(0, 32).should == "415fad6271580a531d4179bc891d87a6" }
      end
    end

    context "Test case 6" do
      let(:key) { "\xaa" * 131 }
      let(:data) { "Test Using Larger Than Block-Size Key - Hash Key First" }

      context "SHA-224" do
        let(:digest) { Krypt::Digest::SHA224.new }
        it { subject.should == "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e" }
      end

      context "SHA-256" do
        let(:digest) { Krypt::Digest::SHA256.new }
        it { subject.should == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" }
      end

      context "SHA-384" do
        let(:digest) { Krypt::Digest::SHA384.new }
        it { subject.should == "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952" }
      end

      context "SHA-512" do
        let(:digest) { Krypt::Digest::SHA512.new }
        it { subject.should == "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598" }
      end
    end

    context "Test case 7" do
      let(:key) { "\xaa" * 131 }
      let(:data) { "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm." }

      context "SHA-224" do
        let(:digest) { Krypt::Digest::SHA224.new }
        it { subject.should == "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1" }
      end

      context "SHA-256" do
        let(:digest) { Krypt::Digest::SHA256.new }
        it { subject.should == "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" }
      end

      context "SHA-384" do
        let(:digest) { Krypt::Digest::SHA384.new }
        it { subject.should == "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e" }
      end

      context "SHA-512" do
        let(:digest) { Krypt::Digest::SHA512.new }
        it { subject.should == "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58" }
      end
    end
  end

end
