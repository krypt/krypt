require 'rspec'
require 'krypt'
require 'stringio'

describe "Krypt::Base64 integration" do 

  let(:dec) { Krypt::Base64::Decoder }
  let(:enc) { Krypt::Base64::Encoder }

  require_relative 'identity_shared'

  describe "Encoder and Decoder stacked on top of each other" do
    it_behaves_like "Identity codec", Krypt::Base64::Encoder, Krypt::Base64::Decoder
  end
end

