module Krypt::FFI
  
  class Digest
    include Krypt::FFI::LibC

    def initialize(provider, type)
      unless (@handle = interface_for_name(provider, type))
        unless (@handle = interface_for_oid(provider, type))
          raise Krypt::Digest::DigestError.new("Unknown digest algorithm: #{type}")
        end
      end
    end

    def reset
      result = @handle.interface[:md_reset].call(@handle.container)
      raise_on_error("Error while resetting digest", result)
      self
    end

    def update(data)
      result = @handle.interface[:md_update].call(@handle.container, data, data.length)
      raise_on_error("Error while updating digest", result)
      self
    end
    alias << update

    def digest(data=nil)
      if data
        ret = digest_once(data)
      else
        ret = digest_finalize
      end
      reset
      ret
    end

    def hexdigest(data=nil)
      Krypt::Hex.encode(digest(data))
    end

    def digest_length
      read_length(@handle.interface[:md_digest_length])
    end

    def block_length
      read_length(@handle.interface[:md_block_length])
    end

    def name
      name_ptr = FFI::MemoryPointer.new(:pointer)
      result = @handle.interface[:md_name].call(@handle.container, name_ptr)
      raise_on_error("Error while obtaining digest name", result)

      name_ptr.read_pointer.get_bytes(0)
    end

    private

      def raise_on_error(msg, result)
        raise Krypt::Digest::DigestError.new(msg) unless result == Krypt::FFI::ProviderAPI::KRYPT_OK
      end

      def digest_once(data)
        digest_ptr = ::FFI::MemoryPointer.new(:pointer)
        size_ptr = ::FFI::MemoryPointer.new(:pointer)
        result = @handle.interface[:md_digest].call(@handle.container, data, data.length, digest_ptr, size_ptr)
        raise_on_error("Error while computing digest", result)

        digest_ptr = digest_ptr.read_pointer
        size = size_ptr.read_int
        ret = digest_ptr.get_bytes(0, size)
        free(digest_ptr)
        ret
      end

      def digest_finalize
        digest_ptr = ::FFI::MemoryPointer.new(:pointer)
        size_ptr = ::FFI::MemoryPointer.new(:pointer)
        result = @handle.interface[:md_final].call(@handle.container, digest_ptr, size_ptr)
        raise_on_error("Error while computing digest", result)

        digest_ptr = digest_ptr.read_pointer
        size = size_ptr.read_int
        ret = digest_ptr.get_bytes(0, size)
        free(digest_ptr)
        ret
      end

      def read_length(fp)
        size_ptr = ::FFI::MemoryPointer.new(:pointer)
        result = fp.call(@handle.container, size_ptr)
        raise_on_error("Error while obtaining block length", result)

        size_ptr.read_int
      end

      def interface_for_name(provider, name)
        digest_ctor = provider[:md_new_name]
        get_native_handle(provider, digest_ctor, name)
      end

      def interface_for_oid(provider, oid)
        digest_ctor = provider[:md_new_oid]
        get_native_handle(provider, digest_ctor, oid)
      end

      def get_native_handle(provider, digest_ctor, type)
        container_ptr = digest_ctor.call(provider, type)
        return nil if nil == container_ptr || container_ptr.null?

        container = Krypt::FFI::ProviderAPI::KryptMd.new(container_ptr)
        interface_ptr = container[:methods]
        interface = Krypt::FFI::ProviderAPI::DigestInterface.new(interface_ptr)
        NativeHandle.new(container, interface)
      end

    class NativeHandle
      attr_reader :container
      attr_reader :interface

      def initialize(container, interface)
        @container = container
        @interface = interface
      end
    end

  end
end
