module Krypt
  module Provider

    PROVIDERS = {}
    PROVIDER_LIST = []

    class AlreadyExistsError < StandardError; end

    class ServiceNotAvailableError < StandardError; end

    module_function

      def register(name, provider)
        raise AlreadyExistsError.new("There already is a Provider named #{name}") if PROVIDERS.has_key?(name)
        PROVIDERS[name] = provider
        PROVIDER_LIST << name
      end

      def by_name(name)
        PROVIDERS[name]
      end

      def default=(provider)
        raise AlreadyExistsError.new("There already is a default Provider") if PROVIDERS.has_key?(:default)
        PROVIDERS[:default] = provider
        PROVIDER_LIST.insert(0, :default)
      end

      def default
        PROVIDERS[:default]
      end

      def remove(name)
        raise KryptError.new("Cannot remove the default Provider") if name == :default
        PROVIDERS.delete(name)
        PROVIDER_LIST.delete(name)
      end

      def service(f)
        PROVIDER_LIST.reverse.each do |name| 
          begin
            service = PROVIDERS[name].instance_eval(&f)
            return service if service
          rescue NameError
          end
        end
        raise ServiceNotAvailableError.new("The requested service is not available")
      end

  end
end
