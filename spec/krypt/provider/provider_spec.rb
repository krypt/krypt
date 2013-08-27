require 'rspec'
require 'krypt'

describe "Krypt::Provider" do 

  before(:each) do
    Krypt::Provider::PROVIDERS.clear
    Krypt::Provider::PROVIDER_LIST.clear
  end

  let(:prov) { Krypt::Provider }

  describe "#register=" do
    it "takes an optional name parameter" do
      -> { prov.register(:name, Object.new) }.should_not raise_error
    end

    it "takes the name from the provider directly if none is provided" do
      p1 = Object.new
      p2 = Object.new
      def p2.name
        "test"
      end
      -> { prov.register(p1) }.should raise_error NoMethodError
      -> { prov.register(p2) }.should_not raise_error
    end

    it "does not allow to register a provider twice under the same name" do
      prov.register(Object.new, :name)
      -> { prov.register(Object.new, :name) }.should raise_error prov::AlreadyExistsError
    end
  end

  describe "#remove" do
    it "does allow to remove a registered provider" do
      p1 = Object.new
      def p1.name 
        "test"
      end
      -> { prov.register(p1) }.should_not raise_error
      -> { prov.remove(p1.name) }.should_not raise_error
    end
    it "does allow to remove a provider and register again" do
      p1 = Object.new
      def p1.name 
        "test"
      end
      -> { prov.register(p1) }.should_not raise_error
      -> { prov.remove(p1.name) }.should_not raise_error
      -> { prov.register(p1) }.should_not raise_error
    end
    it "returns nil if a provider with a given name does not exist" do
      prov.remove(:name).should be_nil
    end
  end

  describe "#by_name" do
    it "returns nil if a provider with a given name does not exist" do
      prov.by_name(:name).should be_nil
    end

    context "returns the provider that has been assigned to a given name" do
      let(:instance) { Object.new }
      specify do
        prov.register(instance, :name)
        prov.by_name(:name).should eq(instance)
      end
    end
  end

  describe "#service" do
    let(:provider_a) do
      Class.new do
        def new_service(klass, *args)
          return :A if klass == Krypt::Digest || klass == String
          nil
        end
      end.new
    end

    let(:provider_b) do
      Class.new do
        def new_service(klass, *args)
          return :B if klass == Krypt::Digest || klass == Integer
          nil
        end
      end.new
    end

    context "returns provider features based on the order they were registered" do
      it "raises ServiceNotAvailableError if a requested feature is not supported by any provider" do
        prov.register(provider_a, :a)
        prov.register(provider_b, :b)
        -> { prov.new_service(Object, "test") }.should raise_error prov::ServiceNotAvailableError
      end

      it "finds a service only available in a specific provider" do
        prov.register(provider_a, :a)
        prov.register(provider_b, :b)
        prov.new_service(String).should eq(:A)
        prov.new_service(Integer).should eq(:B)
      end

      context "returns the service of the provider registered last if the service is supported by more than one provider" do
        specify "first a, then b" do
          prov.register(provider_a, :a)
          prov.register(provider_b, :b)
          prov.new_service(Krypt::Digest).should eq(:B)
        end

        specify "first b, then a" do
          prov.register(provider_b, :b)
          prov.register(provider_a, :a)
          prov.new_service(Krypt::Digest).should eq(:A)
        end
      end
    end
  end 

end
