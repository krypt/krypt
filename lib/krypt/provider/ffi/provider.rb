module Krypt::FFI
  class Provider

    def initialize(native_provider)
      @provider = Krypt::FFI::ProviderAPI::ProviderInterface.new(native_provider)
      @provider[:init].call(@provider, nil)
    end

    def name
      @provider[:name]
    end

    def new_service(klass, *args)
      return new_digest(*args) if klass == Krypt::Digest
      nil
    end

    def finalize
      @provider[:finalize].call(@provider)
    end

    private
      
      def new_digest(name_or_oid)
        Krypt::FFI::Digest.new(@provider, name_or_oid)
      end

  end
end
