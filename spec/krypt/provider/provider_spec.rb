require 'rspec'
require 'krypt'

describe "Krypt::Provider" do 

  before(:each) do
    Krypt::Provider::PROVIDERS.clear
    Krypt::Provider::PROVIDER_LIST.clear
  end

  let(:prov) { Krypt::Provider }

  describe "#default=" do
    it "can only be called once" do
      prov.default = Object.new
      -> { prov.default = Object.new }.should raise_error prov::AlreadyExistsError
    end
  end

  describe "#default" do
    it "returns nil if no default provider has been set" do
      prov.default.should be_nil
    end

    context "returns the provider that has been assigned as default provider" do
      let(:instance) { Object.new }
      specify do
        prov.default = instance
        prov.default.should eq(instance)
      end
    end
  end

  describe "#register=" do
    it "does not allow to register a provider twice under the same name" do
      prov.register(:name, Object.new)
      -> { prov.register(:name, Object.new) }.should raise_error prov::AlreadyExistsError
    end
  end

  describe "#by_name" do
    it "returns nil if a provider with a given name does not exist" do
      prov.by_name(:name).should be_nil
    end

    context "returns the provider that has been assigned to a given name" do
      let(:instance) { Object.new }
      specify do
        prov.register(:name, instance)
        prov.by_name(:name).should eq(instance)
      end
    end
  end

  describe "#service" do
    let (:default_provider) do
      Class.new do
        def test_service
          :default
        end
      end.new
    end

    let(:provider_a) do
      Class.new do
        def test_service
          :A
        end

        def a_specific
          :A
        end
      end.new
    end

    let(:provider_b) do
      Class.new do
        def test_service
          :B
        end

        def b_specific
          :B
        end
      end.new
    end

    context "returns provider features based on the order they were registered" do
      it "considers the default provider as the last provider" do
        prov.default = default_provider
        prov.service(->(pr) { test_service }).should eq(:default)
        prov.register(:a, provider_a)
        prov.service(->(pr) { test_service }).should eq(:A)
        prov.register(:b, provider_b)
        prov.service(->(pr) { test_service }).should eq(:B)
      end

      it "considers the default provider as the last provider even if another service was registered before" do
        prov.register(:name, provider_a)
        prov.default = default_provider
        prov.service(->(pr) { test_service }).should eq(:A)
      end

      it "raises ServiceNotAvailableError if a requested feature is not supported by any provider" do
        prov.default = default_provider
        prov.register(:name, provider_a)
        -> { prov.service(->(pr) { not_available_service }) }.should raise_error prov::ServiceNotAvailableError
      end

      it "finds a service only available in a specific provider" do
        prov.default = default_provider
        prov.register(:a, provider_a)
        prov.register(:b, provider_b)
        prov.service(->(pr) { a_specific }).should eq(:A)
        prov.service(->(pr) { b_specific }).should eq(:B)
      end

    end
  end 

end
